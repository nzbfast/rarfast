//! BLAKE2sp as RAR 5 uses it for member hashes (spec L 3.3).
//!
//! Eight BLAKE2s leaves, 64-byte block `b` dealt to leaf `b mod 8`, the
//! eight 32-byte leaf digests hashed by a depth-1 root. The kernel is
//! [`lanes`]: four leaves advance together in the lanes of one register,
//! because a whole 512-byte GROUP gives every leaf one block at the same
//! counter and none of them its last. Two such halves cover the eight.
//!
//! Two arrangements, chosen by input size and the caller's worker
//! allowance and never by content:
//!
//! - the **single-thread kernel**, both halves on the calling thread. It is
//!   the default everywhere (spec L question 6), so a caller that passes
//!   one worker - a download pipeline, for one - keeps its CPU;
//! - the **leaf team**, the leaves on a resident pool, which runs only
//!   when the caller allows workers AND a batch of at least
//!   [`POOL_MIN_BATCH`] has arrived.
//!
//! Both give the digest of 3.3.1 for every input and every chunking.
//!
//! # Working memory
//!
//! Neither entry point ever holds a second copy of the input. The
//! one-shot [`blake2sp`] absorbs the groups where they lie and allocates
//! nothing at all; the streaming [`Blake2sp`] does the same for any feed
//! worth the kernel on its own, and stages smaller ones in one heap block
//! of [`BUFFER`] bytes taken at construction. Peak working memory is
//! therefore a constant - 525,312 bytes - whatever the input size and
//! whatever the chunking, which is what spec L 7 asks for (RSS no higher
//! than the old engine's) and more than spec L 3.3.2 requires (one block
//! per leaf held back).
//!
//! One arrangement holds more, and it is still a constant: a stream that
//! LENDS its full stages to a team of eight (aarch64, a feed of runs under
//! the in-place threshold) holds a second stage while one is in flight,
//! and once it has lent `SUSTAINED_AFTER` bytes the pair is of
//! `SUSTAINED_STAGE` bytes each, 2 MiB and the hold, so that a long stream
//! hands the team a quarter as many batches. See `Blake2sp::lend_stage`.
//! A stream whose feeder is busy between feeds (a decoded member) takes
//! that arrangement for its large feeds too, which it used to hash in
//! place while the feeder waited: see `Feeder`. On x86-64, where the
//! kernel behind the seam is one thread, ONLY such a stream lends, and it
//! lends to one helper thread of this module's own: see `beside`.
//!
//! What lending holds, as figures: two stages of `SUSTAINED_STAGE` at the
//! most and never a third, 4,196,352 bytes (`LENDING_STAGES`), held by
//! at most `PAIRS_MOST` (two) hashers of a process at once; and on x86-64
//! the helper threads, at most `HELPERS_MOST` (four) in a process at
//! once, parked when no stream has them. `beside` states what a library
//! caller holds while a hasher lives and after it is dropped. On aarch64
//! a stage is lent to the team the allowance already builds, and lending
//! starts no thread.
//!
//! One more holds a constant too: on aarch64 a STORED member read at a
//! width above two copies each feed it would hash in place into stages of
//! its own and RELAYS them to the team, so no feed is joined (see
//! `Blake2sp::relay_feed`). It holds `RELAY_STAGES` stages of
//! `RELAY_STAGE` bytes, 6 MiB, CHARGED to the operation's working memory
//! while the hasher lives, held by at most `RELAYS_MOST` (two) hashers of a
//! process at once; and the relay's threads, one per share, parked between
//! streams as the team's are.
//!
//! # What a chunked caller costs over a one-shot one
//!
//! A memcpy, and as little of one as each box can bear. A streaming
//! hasher cannot keep a borrow that ends with `update`, so bytes it is
//! not ready to hand over have to be gathered somewhere; what it CAN do
//! is hand over as much of the caller's own buffer as the kernel will
//! take, where it lies. [`Blake2sp::update`] does that for every feed
//! that clears
//! [`ABSORB_MIN_BATCH`](crate::carry::wiring::blake2sp::ABSORB_MIN_BATCH),
//! the smallest run the kernel behind the seam wants handed over, and
//! copies only the cold start and, per call, at most a group of alignment
//! and the hold. So the copy is a constant per call and not a share of
//! the stream.
//!
//! It used to be the whole stream, and that is what the chunked bench
//! legs were paying for off aarch64: a second pass over every byte that
//! the one-shot entry point never makes, on a box whose kernel is one
//! thread with no dispatch for a gathered batch to amortise. On aarch64
//! the gather earns itself back - a run under the team's pool threshold
//! would leave the team idle and hash at one worker - so there
//! [`ABSORB_MIN_BATCH`] IS that threshold and only feeds above it are
//! taken in place. The constant is the seam's, beside the kernel whose
//! costs decide it, and this module reads it rather than choosing it.
//!
//! [`ABSORB_MIN_BATCH`]: crate::carry::wiring::blake2sp::ABSORB_MIN_BATCH
//!
//! # The dispatch gate, and the open question on its figure
//!
//! The batch a streaming hasher hands the kernel is [`BUFFER`]'s worth at
//! a time, and [`BUFFER`] is the CARRIED kernel's own pool threshold plus
//! the hold, read from that kernel at
//! [`crate::carry::wiring::blake2sp::POOL_MIN_BATCH`] rather than
//! repeated here. The pairing is deliberate and it is the old engine's
//! own: below its threshold the carried team starts seven threads for
//! every call and leaks about 2,700 bytes of each, which is what made
//! `l/blake2sp/chunk256k-8w` read 0.273x of the old engine while this
//! hasher staged 64 KiB. [`Blake2sp::dispatch`] says how both the thread
//! start and the leak are made unreachable from here rather than merely
//! unlikely. Measured, that took the leg from 0.273x to 0.694x and its
//! CPU from 0.1428 to 0.1004 seconds.
//!
//! **What was left of that leg's gap was the staging copy, and the
//! copy is now mostly gone.** A chunked oracle adapter arrived first and
//! settled what the copy was worth: fed the same 256 KiB chunks, the old
//! engine pays the same copy and lands within rarkit's interval
//! (`l/blake2sp/chunk256k-8w-vs8w` at 1.003x to 1.030x, CPU equal to
//! three decimal places), so the `chunk*` legs against the ONE-SHOT old
//! arm are a ceiling and never were a like-for-like gate leg. What the
//! adapter could not do is make the copy free, and off aarch64 - where
//! the `-vs8w` legs have no oracle arm at all and the ceiling legs are
//! all there is to read - it is the whole of the shortfall. The section
//! above disposes of it: the caller's own buffer is absorbed where it
//! lies.
//!
//! **This is not the figure spec L question 6 answers with, and the
//! difference is an open question on the specification.** Question 6 was answered on
//! 19 Sep 2026 as work PER DISPATCH: the team engages only when one
//! dispatch would give every worker at least 1 MiB, so at least 8 MiB at
//! once with eight workers. Staging 8 MiB was not implemented here, for a
//! reason that is a measurement and not a preference: NEITHER reading
//! reaches the 0.97x wall gate on the chunked leg, because what is left
//! of that gap is the staging copy and not the dispatch (see below), so
//! the 8 MiB buys nothing on wall that the 512 KiB does not. It does cost
//! 8 MiB of resident working memory, about 12 percent over the old
//! engine's peak on the 64 MiB leg, where 512 KiB measured 1 MiB and
//! 0.76 percent. The project's rule of the same day reads peak-RSS targets
//! with a tolerance of 1 MiB or 2 percent, whichever is larger, and
//! 8 MiB is well outside it while 512 KiB is inside it. The third
//! follow-up was to
//! stage to the carried kernel's pool threshold instead, which is
//! 512 KiB and is the arrangement the old engine measures at. The two
//! properties question 6 was written to
//! protect are both kept whichever figure is right, and are kept HERE: a
//! caller that passes one worker never meets a team, and neither does a
//! hasher whose whole input is too small to want one. What is not kept is
//! the 1 MiB per worker. **The figure is still open.**
//!
//! [`TEAM_MIN_BATCH`] is untouched by this and still reads 8 MiB: it
//! gates package L's OWN lane kernel, whose parallel arm joins per call
//! and was measured to cost more CPU than it buys below that size.
//!
//! # The same defect from the kernel's side
//!
//! The thread start and the leak described above were the CARRIED team's,
//! and it was mended there as well, the same day and independently.
//! What changed is the test the
//! team applies before it builds its resident pool: it now counts the
//! bytes absorbed SO FAR rather than the size of the batch in front of
//! it, which means no `absorb` at any size can start a thread or take an
//! allocation. The staging this module does is therefore a second line of
//! defence, not the only thing standing between a caller and those costs.
//!
//! **That is what let the staging copy go, and the choice it left is
//! made at the seam.** A kernel that no longer wants a 512 KiB batch does
//! not need this hasher to gather one, so a feed it will take is absorbed
//! WHERE IT LIES - no memcpy. What it costs is a dispatch per feed
//! instead of one per stage, about 95 microseconds of wall on a loaded
//! box as measured, and that is why the threshold is the
//! kernel's own figure and not a number this module picks: off aarch64
//! an `absorb` is a plain streaming call and a gather is pure loss, while
//! on aarch64 a run below the pool threshold would leave the team idle.
//! [`BUFFER`] stays what it is, because the COLD start still has to hand
//! over a batch that clears the threshold: the kernel is chosen once, on
//! the first batch, and a smaller one pins the stream to one worker.
//!
//! The two arms read `workers` differently, which the same kernel change
//! settled. [`lanes`] reads it as what THIS batch may use, and the gate
//! for that is applied here. The carried team reads the allowance the
//! hasher was CONSTRUCTED with. The two agree where it matters: ask for
//! one worker and no arm starts a thread. `carry/wiring.rs` states it at
//! the seam itself.

pub(crate) mod lanes;

// THE SEAM. Everything this module does to reach a carried kernel is this
// import and the two constructors below it; there is no third place, and
// `Crc32::update` in the parent module is the same arrangement.
//
// What is on the other side of it depends on the box. On aarch64 it is the
// carried many-lane team, taken where the machine and the allowance the
// caller gave make it worth taking, and [`lanes`] otherwise. Off aarch64 it
// is the carried many-way SIMD kernel, because [`lanes`] has no vector arm
// there at all and compresses a leaf at a time - which is what read 0.141x
// to 0.173x of the old engine on x86-64, the worst figure the project has
// recorded. That kernel spends no thread, so the worker count and the team
// gate above reach nothing off aarch64.
//
// [`crate::carry::wiring::blake2sp::Leaves`] presents exactly the surface
// [`lanes::Leaves`] does, which is the whole reason the seam is this small:
// no other line of this module knows which side it is on. The kernels
// themselves are carried and are not this package's to write or to own,
// and spec L's erratum of 18 Sep 2026 is what puts them there. Which
// target gets which kernel, and why, is stated in `carry/wiring.rs`;
// each choice there was measured.
#[cfg(not(target_arch = "x86_64"))]
use crate::carry::wiring::blake2sp::Leaves;
#[cfg(target_arch = "aarch64")]
use crate::carry::wiring::blake2sp::Lent;
use crate::carry::wiring::blake2sp::{ABSORB_MIN_BATCH, POOL_MIN_BATCH};
// On x86-64 the kernel behind the seam is one thread, and the leaves this
// module holds are that kernel with a helper thread of this module's own
// to hash a lent stage: see `beside`.
#[cfg(target_arch = "x86_64")]
use beside::{Leaves, Lent};
use lanes::{DIGEST, GROUP};

/// x86-64's stand-in for a team to lend to: the kernel behind the seam and
/// ONE helper thread that hashes a lent stage with it.
///
/// **Why.** Counted on a Zen 4 (8 cores, 12 Oct 2026, a plain build): `t`
/// of one compressed member with a BLAKE2sp digest hashed every byte in
/// place on the thread the decode delivers on, 0.36 s of a 1.09 s wall on
/// 2 GiB, in series with the decode (the same member under CRC32: 0.73 s).
/// The kernel here is one thread and wants no team; what the stream wants
/// is for that one thread not to be the feeder's. So the leaves this
/// module holds on x86-64 are the seam's, with the surface the aarch64
/// seam has for lending: `lend` hands the kernel itself and a stage to a
/// helper thread and returns at once, and whatever next needs the leaves
/// waits for them to land. One flight at a time, so the stream's order is
/// kept by construction, and the digest is the kernel's own whichever
/// thread ran it.
///
/// A helper is a parked thread, started at a stream's first lend and kept
/// on a list, so a hasher reused member after member starts none.
/// Nothing lends at an allowance of two or less (a caller that passes one
/// worker keeps its thread, and a stream that shares the machine with
/// others adds no thread to it), nor on a box with one core, nor for a
/// member read at a width of one (`Blake2sp::forms_apply`).
///
/// # The bound on helpers, and what a caller holds
///
/// **At most `HELPERS_MOST` helper threads exist in a process at any
/// moment**, flying or parked, however many hashers it holds and however
/// they are used. A helper is out with a stream only for one flight at a
/// time (it is taken at a lend and parked again when that flight lands),
/// and a stream that finds every helper out and the ceiling reached is
/// REFUSED: it hashes in place to its end, as it did before this form, so
/// the ceiling can cost wall and can never cost a digest.
///
/// What a LIBRARY caller holds for this module, stated:
/// - while a hasher lives and is not lending: nothing but the hasher (one
///   stage, `BUFFER` bytes);
/// - while a hasher lends: two stages and never a third, each
///   `SUSTAINED_STAGE` bytes at most (`LENDING_STAGES`, 4,196,352 bytes),
///   kept while its members hand their verdict on and let go when one
///   does not; at most `PAIRS_MOST` hashers of a process hold that longer
///   pair at once, and one over the ceiling lends the two stages of
///   `BUFFER` bytes it has; and one helper thread for the length of each
///   flight;
/// - after every hasher is dropped: no stage, and the helper threads that
///   were started, parked for the life of the process, `HELPERS_MOST` at
///   the very most. A parked helper holds its desk (a mutex, a condition
///   variable and an empty slot) and its stack, which is the standard
///   library's for a spawned thread (2 MiB of address space unless
///   `RUST_MIN_STACK` says otherwise, of which a helper touches what one
///   pass of the kernel needs); it holds no stage and no kernel.
///
/// A helper never ends: ending and starting one per member would be a
/// thread start per member on a solid chain. The ceiling is what bounds
/// them.
///
/// **Why `HELPERS_MOST` is four.** A helper is wanted by a stream that
/// has its whole allowance, and the census (`share`) gives the whole
/// allowance to a stream that hashes ALONE: one that begins beside
/// another is built at the shared team and never lends. So one lending
/// stream is the shipped case, and more than one arises only where a
/// stream that began alone is still running when others begin alone
/// after it (a stream is never narrowed), or where clones of a lending
/// stream run side by side. Four leaves room for those and keeps what a
/// process can be left holding to four parked threads.
#[cfg(target_arch = "x86_64")]
mod beside {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};

    use super::{DIGEST, SHARED_TEAM};
    use crate::carry::wiring::blake2sp::Leaves as Kernel;

    /// A stage lent for one flight. The aarch64 seam's type, so the hasher
    /// is one text on both; here it is never shared, only moved.
    pub(super) type Lent = Arc<Box<[u8]>>;

    /// One lent batch: the kernel, and the stage whose first `len` bytes
    /// it is to absorb.
    struct Flight {
        kernel: Kernel,
        stage: Lent,
        len: usize,
    }

    /// Where a flight is.
    enum Slot {
        Empty,
        Posted(Flight),
        Flying,
        Landed(Flight),
        /// The helper unwound with a flight in hand.
        Lost,
    }

    /// What a hasher and its helper share.
    struct Desk {
        slot: Mutex<Slot>,
        turn: Condvar,
        /// The helpers this desk's thread is counted among.
        home: &'static Helpers,
    }

    /// The most helper threads a process holds at once, flying or parked.
    /// See the module comment for what it bounds and why it is four.
    pub(super) const HELPERS_MOST: usize = 4;

    /// The helper threads of a process: those with no flight, each parked
    /// on its desk, and the count of all that are alive.
    pub(super) struct Helpers {
        parked: Mutex<Vec<Arc<Desk>>>,
        /// Helper threads alive, flying or parked: never above
        /// [`HELPERS_MOST`]. A place is claimed BEFORE a thread is
        /// started and given back if it cannot be, or if it unwinds.
        alive: AtomicUsize,
    }

    impl Helpers {
        const fn new() -> Helpers {
            Helpers {
                parked: Mutex::new(Vec::new()),
                alive: AtomicUsize::new(0),
            }
        }

        /// Helper threads alive, flying or parked.
        #[cfg(test)]
        pub(super) fn alive(&self) -> usize {
            self.alive.load(Ordering::Relaxed)
        }

        /// Helper threads parked with no flight.
        #[cfg(test)]
        pub(super) fn parked(&self) -> usize {
            held(&self.parked).len()
        }

        /// Whether a stream that asks now would be given a helper: one
        /// is parked, or the ceiling leaves room to start one.
        fn has_room(&self) -> bool {
            self.alive.load(Ordering::Relaxed) < HELPERS_MOST || !held(&self.parked).is_empty()
        }

        /// A place under the ceiling for one more thread, or `false`.
        fn claim(&self) -> bool {
            self.alive
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < HELPERS_MOST).then_some(n + 1)
                })
                .is_ok()
        }
    }

    /// The process's helpers.
    #[cfg(not(test))]
    static HELPERS: Helpers = Helpers::new();

    // Per THREAD under `cfg(test)`, as the stream census is and for the
    // same reason: the unit tests run on parallel threads, and a test
    // that fills the ceiling must not refuse another test's stream.
    #[cfg(test)]
    thread_local! {
        static HELPERS_HERE: &'static Helpers = Box::leak(Box::new(Helpers::new()));
    }

    /// The helpers a stream on this thread draws on.
    pub(super) fn helpers() -> &'static Helpers {
        #[cfg(not(test))]
        return &HELPERS;
        #[cfg(test)]
        return HELPERS_HERE.with(|here| *here);
    }

    fn held<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
        lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks the flight lost if the helper unwinds while it has one, so
    /// the hasher that waits for it is told and does not wait for ever.
    struct Unwound<'a>(&'a Desk);

    impl Drop for Unwound<'_> {
        fn drop(&mut self) {
            // The thread is ending: its place under the ceiling is free.
            self.0.home.alive.fetch_sub(1, Ordering::Relaxed);
            *held(&self.0.slot) = Slot::Lost;
            self.0.turn.notify_all();
        }
    }

    /// The helper thread: absorb each posted flight and land it.
    fn serve(desk: &Desk) {
        loop {
            let mut slot = held(&desk.slot);
            let mut flight = loop {
                match std::mem::replace(&mut *slot, Slot::Flying) {
                    Slot::Posted(flight) => break flight,
                    other => {
                        *slot = other;
                        slot = desk.turn.wait(slot).unwrap_or_else(PoisonError::into_inner);
                    }
                }
            };
            drop(slot);
            let unwound = Unwound(desk);
            // A lent batch is under the size the kernel's own spread
            // begins at, and the helper is the one thread it is given.
            flight.kernel.absorb(&flight.stage[..flight.len], 1);
            std::mem::forget(unwound);
            *held(&desk.slot) = Slot::Landed(flight);
            desk.turn.notify_all();
        }
    }

    #[cfg(test)]
    thread_local! {
        /// Helpers this thread's hashers have taken, parked or new: a
        /// unit test's proof that a stream took none.
        pub(super) static DESKS_TAKEN: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    /// A parked helper, or a new one under the ceiling; `None` where
    /// every helper is out and [`HELPERS_MOST`] are alive, or where no
    /// thread can be started, and the stream then hashes in place.
    fn a_desk() -> Option<Arc<Desk>> {
        let home = helpers();
        if let Some(desk) = held(&home.parked).pop() {
            #[cfg(test)]
            DESKS_TAKEN.with(|n| n.set(n.get() + 1));
            return Some(desk);
        }
        if !home.claim() {
            return None;
        }
        let desk = Arc::new(Desk {
            slot: Mutex::new(Slot::Empty),
            turn: Condvar::new(),
            home,
        });
        let theirs = Arc::clone(&desk);
        let started = std::thread::Builder::new()
            .name("rarkit-blake2sp".to_owned())
            .spawn(move || serve(&theirs));
        if started.is_err() {
            home.alive.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        #[cfg(test)]
        DESKS_TAKEN.with(|n| n.set(n.get() + 1));
        Some(desk)
    }

    /// Wait for `desk`'s flight to land and take it; `None` if it was
    /// lost.
    fn landed(desk: &Desk) -> Option<Flight> {
        let mut slot = held(&desk.slot);
        loop {
            match std::mem::replace(&mut *slot, Slot::Empty) {
                Slot::Landed(flight) => return Some(flight),
                Slot::Lost => return None,
                other => {
                    *slot = other;
                    slot = desk.turn.wait(slot).unwrap_or_else(PoisonError::into_inner);
                }
            }
        }
    }

    /// Whether this box has a core for the helper beside the feeder.
    fn second_core() -> bool {
        static FITS: OnceLock<bool> = OnceLock::new();
        *FITS.get_or_init(|| std::thread::available_parallelism().is_ok_and(|n| n.get() >= 2))
    }

    /// The seam's leaves, and the flight they may be out on.
    pub(super) struct Leaves {
        /// `None` exactly while `out` holds a flight.
        kernel: Option<Kernel>,
        /// The allowance the stream hashes at, which decides only whether
        /// it lends: the kernel is one thread at every figure.
        allowance: usize,
        /// The desk of the helper that has the kernel now.
        out: Option<Arc<Desk>>,
        /// A landed stage the hasher has not yet taken back.
        back: Option<Lent>,
    }

    impl Leaves {
        pub(super) fn with_workers(workers: usize) -> Leaves {
            Leaves {
                kernel: Some(Kernel::with_workers(workers)),
                allowance: workers.max(1),
                out: None,
                back: None,
            }
        }

        /// Wait for the flight that is out, if one is, and take the kernel
        /// and the stage back; the helper parks.
        fn land(&mut self) {
            let Some(desk) = self.out.take() else {
                return;
            };
            let flight = landed(&desk).expect("the BLAKE2sp helper thread kept its batch");
            held(&desk.home.parked).push(desk);
            self.kernel = Some(flight.kernel);
            self.back = Some(flight.stage);
        }

        fn kernel(&mut self) -> &mut Kernel {
            self.land();
            self.kernel
                .as_mut()
                .expect("the kernel is here once landed")
        }

        pub(super) fn absorb(&mut self, groups: &[u8], workers: usize) {
            self.kernel().absorb(groups, workers);
        }

        pub(super) fn absorb_pieces(&mut self, pieces: &[&[u8]], workers: usize) {
            self.kernel().absorb_pieces(pieces, workers);
        }

        /// The allowance the NEXT batches are judged at (the re-share,
        /// which only ever widens it).
        pub(super) fn set_allowance(&mut self, workers: usize) {
            self.allowance = workers.max(1);
        }

        /// Whether [`Self::lend`] would take a batch now: the allowance
        /// and the box allow a helper, and one is to be had (this
        /// stream's own, still out on its last flight, or one under the
        /// ceiling). A stream told no hashes in place to its end.
        pub(super) fn will_lend(&self, len: usize) -> bool {
            let _ = len;
            self.allowance > SHARED_TEAM
                && second_core()
                && (self.out.is_some() || helpers().has_room())
        }

        /// Hand the kernel and the first `len` bytes of `stage` (whole
        /// groups, none of them any leaf's last) to a helper and return at
        /// once; `Err` gives the stage back untouched where nothing takes
        /// it, and the caller absorbs it in place.
        pub(super) fn lend(&mut self, stage: Lent, len: usize) -> Result<(), Lent> {
            if !self.will_lend(len) {
                return Err(stage);
            }
            self.land();
            let Some(desk) = a_desk() else {
                return Err(stage);
            };
            let kernel = self.kernel.take().expect("the kernel is here once landed");
            *held(&desk.slot) = Slot::Posted(Flight { kernel, stage, len });
            desk.turn.notify_all();
            self.out = Some(desk);
            Ok(())
        }

        /// Land any lent batch and give its stage back to gather into
        /// again; `None` if nothing was lent since the last call.
        pub(super) fn settle(&mut self) -> Option<Lent> {
            self.land();
            self.back.take()
        }

        pub(super) fn finish(mut self, tail: &[u8]) -> [u8; DIGEST] {
            self.land();
            let kernel = self.kernel.take().expect("the kernel is here once landed");
            kernel.finish(tail)
        }
    }

    /// A clone is the leaves as they will be once the flight that is out
    /// has landed: it waits for the landing and leaves the flight on the
    /// desk for its owner.
    impl Clone for Leaves {
        fn clone(&self) -> Leaves {
            let kernel = match &self.out {
                None => self.kernel.clone(),
                Some(desk) => {
                    let mut slot = held(&desk.slot);
                    loop {
                        match &*slot {
                            Slot::Landed(flight) => break Some(flight.kernel.clone()),
                            Slot::Lost => break None,
                            _ => {
                                slot = desk.turn.wait(slot).unwrap_or_else(PoisonError::into_inner);
                            }
                        }
                    }
                }
            };
            Leaves {
                kernel: Some(kernel.expect("the BLAKE2sp helper thread kept its batch")),
                allowance: self.allowance,
                out: None,
                back: None,
            }
        }
    }

    /// Leaves dropped with a flight out wait for it, so the helper parks
    /// with nothing in hand and is there for the next stream.
    impl Drop for Leaves {
        fn drop(&mut self) {
            if let Some(desk) = self.out.take() {
                if landed(&desk).is_some() {
                    held(&desk.home.parked).push(desk);
                }
            }
        }
    }
}

/// Batch below which package L's OWN lane kernel does not spread its two
/// halves over a `rayon::join`. Spec L question 6 names 8 MiB, which is
/// also the old engine's measured knee; joining per 256 KiB instead cost
/// 0.0925 CPU seconds over 64 MiB against 0.0421, which is below the old
/// engine per CPU second, and question 6 exists to prevent exactly that.
///
/// This is NOT the gate on the carried team, which is [`POOL_MIN_BATCH`];
/// see the module comment.
const TEAM_MIN_BATCH: usize = 8 << 20;

/// BLAKE2sp of `data`, on the calling thread. HOT PATH.
///
/// The shipped callers all have a worker allowance to pass and take
/// [`blake2sp_with_workers`]; this is the one-worker form, which the
/// `internals_l` seam and this module's own tests use as the reference
/// every other arrangement is held to.
#[allow(dead_code)]
pub(crate) fn blake2sp(data: &[u8]) -> [u8; DIGEST] {
    hash(data, 1)
}

/// BLAKE2sp of `data`, allowed `workers` units of work in flight.
///
/// The one-shot form of [`Blake2sp::with_workers`], for a caller that has
/// the whole span in hand: a stored member's bytes, or a fragment of one.
/// Whether a team engages is [`team`]'s to say and the input has to be
/// worth one; `workers` is a CEILING and never a demand (API 8.2).
pub(crate) fn blake2sp_with_workers(data: &[u8], workers: usize) -> [u8; DIGEST] {
    hash(data, workers.max(1))
}

/// BLAKE2sp of `data` in one pass, with no copy of the input: the groups
/// are absorbed where they lie and only the tail is gathered.
fn hash(data: &[u8], workers: usize) -> [u8; DIGEST] {
    #[cfg(test)]
    ALLOWANCE.with(|seen| seen.set(workers));
    // The seam: whichever side `Leaves` comes from, it is built with the
    // caller's allowance and nothing below this line knows the difference.
    let _stream = Stream::enter();
    let workers = shared(workers);
    let mut leaves = Leaves::with_workers(workers);
    let tail = whole_groups(data.len());
    leaves.absorb(&data[..tail], team(tail, workers));
    leaves.finish(&data[tail..])
}

/// How much of `len` is groups no leaf can have its last block in: every
/// group but the last TWO, since a leaf must not compress its last block
/// until it knows it is last (3.3.2), and a partial last group leaves the
/// later leaves' last block in the group before it.
fn whole_groups(len: usize) -> usize {
    len.div_ceil(GROUP).saturating_sub(2) * GROUP
}

/// The workers one batch may use.
fn team(batch: usize, workers: usize) -> usize {
    if batch >= TEAM_MIN_BATCH {
        workers
    } else {
        1
    }
}

/// The worker allowance every hasher built from now on takes INSTEAD of
/// its caller's, or 0 for the caller's own. A lab dial,
/// behind a feature of its
/// own that no gate binary turns on, so neither the load nor the layout
/// reaches a measured arm.
#[cfg(feature = "f8x16-probe")]
pub(crate) static TEAM_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// BLAKE2sp streams hashing in this process right now: a streaming hasher
/// from its first byte until it is finished or reset, and a one-shot hash
/// for the length of its call.
///
/// It exists for ONE decision, the width a stream's team is BUILT at. The
/// team of eight is the right arrangement for one stream and the wrong one
/// for many: eight members decoded at once each built one, 56 extra
/// threads on a 32-core box beside the decode lanes, running the scalar
/// leaf kernel at about twice the NEON kernel's CPU per byte. Measured on
/// a 20-core M1 Ultra (one binary against itself,
/// the eight-member rows), a team of TWO for each of eight concurrent
/// members read 1.405x of the shipped wall at 59 percent of its CPU, a
/// team of one 1.136x, a team of four 1.011x; and ONE member alone read
/// 0.609x at a team of two, so a lone stream keeps its whole allowance.
///
/// Per THREAD under `cfg(test)`: the unit tests run on parallel threads,
/// and a test that asserts a team was built must not see another test's
/// streams. The census itself is tested on one thread with several live
/// hashers, which is the same arithmetic.
#[cfg(not(test))]
static STREAMS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
thread_local! {
    static STREAMS_HERE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Count one stream in, or out, of the census.
fn census(delta: isize) {
    #[cfg(not(test))]
    {
        use std::sync::atomic::Ordering::Relaxed;
        if delta > 0 {
            STREAMS.fetch_add(1, Relaxed);
        } else {
            STREAMS.fetch_sub(1, Relaxed);
        }
    }
    #[cfg(test)]
    STREAMS_HERE.with(|n| n.set(n.get().wrapping_add_signed(delta)));
}

/// The streams live now, this one included.
fn live_streams() -> usize {
    #[cfg(not(test))]
    return STREAMS.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    return STREAMS_HERE.with(std::cell::Cell::get);
}

/// One live stream, counted until dropped. A clone is a second stream and
/// counts again.
struct Stream(());

impl Stream {
    fn enter() -> Stream {
        census(1);
        Stream(())
    }
}

impl Clone for Stream {
    fn clone(&self) -> Stream {
        Stream::enter()
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        census(-1);
    }
}

/// The widest team a stream that shares the machine is built at: the
/// carried kernel's two NEON halves on two threads, its cheapest arm per
/// byte that uses more than one core.
const SHARED_TEAM: usize = 2;

/// The allowance a stream builds its team at: the caller's whole allowance
/// when it hashes alone, and at most [`SHARED_TEAM`] when `live` streams
/// hash at once. It moves which threads hash, never a digest.
fn share(workers: usize, live: usize) -> usize {
    if live <= 1 {
        workers
    } else {
        workers.min(SHARED_TEAM)
    }
}

/// [`share`] against the streams live now.
fn shared(workers: usize) -> usize {
    #[cfg(feature = "test-support")]
    if share_is_off() {
        return workers;
    }
    share(workers, live_streams())
}

/// `RARKIT_BLAKE_SHARE=off` builds every team at the caller's whole
/// allowance, which is the arrangement before the census: the BEFORE arm
/// of a before-and-after in ONE gate binary, so the two halves cannot
/// differ by layout. Read once a process.
/// Behind `test-support`, which the gate binary turns on and no shipped
/// build does.
#[cfg(feature = "test-support")]
fn share_is_off() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| std::env::var("RARKIT_BLAKE_SHARE").is_ok_and(|v| v == "off"))
}

/// `RARKIT_BLAKE_RESHARE`: `1` (or `on`) has a stream read the census
/// again at EVERY batch and WIDEN its team to its whole allowance once the
/// streams beside it have finished; `0` (or `off`) reads it once, at the
/// stream's first batch, the arrangement before 2 Oct 2026; anything else,
/// or nothing, is [`RESHARE`]. A stream is never narrowed: one that chose
/// its whole allowance alone keeps it when a neighbour arrives, as it
/// always has (narrowing it too was measured and LOST on a mixed archive,
/// 0.75x to 0.88x on an M1 Ultra: three streams at eight, two and two
/// threads beat three at two on twenty cores). A RUNTIME knob, so one binary carries both arms. It moves
/// which threads hash, never a digest. On aarch64, and on x86-64 where the
/// figure decides only whether a stream lends: elsewhere no arm has a team
/// for a census to size.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(crate) const BLAKE_RESHARE_ENV: &str = "RARKIT_BLAKE_RESHARE";

/// Whether a stream re-reads the census where [`BLAKE_RESHARE_ENV`] says
/// nothing: it does. Counted on 2 Oct 2026 on an M1 Ultra:
/// a 12 GiB member beside its 60 MiB
/// sample chose its team while the sample's stream was alive in 37 pool
/// rows of 82, and then hashed ALL of itself on the two NEON halves (`t`
/// 6.08 s, behind unrar) where the leaf team gives 4.12 s; read one member
/// at a time it never did (36 rows of 36). Its rows there, K=5, widening
/// only: that `t` 5.59 s to 3.21 s, seven big members 5.65 s to 3.56 s, a mixed
/// archive 0.51 s to 0.43 s, and no row of thirteen under 0.989x.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const RESHARE: bool = true;

/// [`BLAKE_RESHARE_ENV`]'s value as an answer.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn reshare_of(value: Option<&str>) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => true,
        Some("0" | "off") => false,
        _ => RESHARE,
    }
}

#[cfg(all(test, any(target_arch = "aarch64", target_arch = "x86_64")))]
thread_local! {
    /// A unit test's answer for [`reshares`], on its own thread.
    static RESHARE_HERE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Whether a stream re-reads the census at every batch: a unit test's
/// answer on its own thread, then the environment's, read once.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn reshares() -> bool {
    #[cfg(test)]
    if let Some(forced) = RESHARE_HERE.with(std::cell::Cell::get) {
        return forced;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| reshare_of(crate::knob::reader_var(BLAKE_RESHARE_ENV).ok().as_deref()))
}

/// The allowance the batch in hand is hashed at, into `chosen`: [`shared`]
/// out of the stream's own figure at its FIRST batch, which builds the
/// leaves; and, under [`reshares`], [`shared`] out of `ceiling` (the
/// allowance the member was armed with, `Blake2sp::workers`, never the
/// figure a neighbour already narrowed) at every batch after it, handed
/// to the leaves where it is WIDER than the stream has.
fn choose(leaves: &mut Option<Leaves>, chosen: &mut usize, ceiling: usize) {
    let Some(built) = leaves else {
        *chosen = shared(*chosen);
        return;
    };
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    if reshares() {
        let now = shared(ceiling);
        if now > *chosen {
            built.set_allowance(now);
            *chosen = now;
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let _ = (built, ceiling);
}

/// A bench count, in a `test-support` build only: the bytes this process's
/// hashers have handed the kernel by each route, LENT to the team (hashed
/// beside whatever the feeding thread does next), dispatched from the
/// stage unlent, and hashed in place while the feeding thread waits. A
/// hasher prints and clears them when it finishes if `RARKIT_BLAKE_COUNT`
/// is set. It is how the feeds a stream gathers and lends (below) were
/// counted before that was written.
#[cfg(feature = "test-support")]
pub(crate) static COUNT_BYTES: [std::sync::atomic::AtomicU64; 3] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];
#[cfg(feature = "test-support")]
fn count_bytes(which: usize, n: usize) {
    COUNT_BYTES[which].fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
}
#[cfg(not(feature = "test-support"))]
#[inline(always)]
fn count_bytes(_which: usize, _n: usize) {}

/// Whether `RARKIT_BLAKE_COUNT` is set, read ONCE a process (a
/// `test-support` build only).
///
/// **Why once, and first at construction.** A read of the environment
/// ALLOCATES on Windows: the name is turned into a wide string on the
/// heap, 38 bytes for this one. Read as each member finished, it was an
/// allocation a member there (`tests/allocations.rs` read 1.001 a member
/// and `tests::a_short_member_never_builds_a_team` a peak of 38 bytes,
/// Windows only: elsewhere a short name goes through a buffer on the
/// stack). So it is read once, and [`Blake2sp::with_workers`] reads it,
/// so the one allocation is the constructor's and never a member's.
#[cfg(feature = "test-support")]
fn counts_printed() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RARKIT_BLAKE_COUNT").is_some())
}

/// What a stream knows of the thread that feeds it, kept while its feeds
/// are hashed in place: how long the hash has held that thread (`busy`),
/// and how long the thread was away between one in-place feed and the
/// next (`away`), over `placed` bytes.
///
/// **Why.** A feed that clears the in-place threshold is hashed where it
/// lies, and the feeding thread waits for the team. That is right when
/// the thread has nothing else to do (the wide read of a stored member
/// joins pieces others read), and wrong when it is the thread a decoder
/// delivers on: counted on an M1 Ultra, 12 Oct 2026, `t` of one
/// compressed member with a BLAKE2sp digest hashed 80 to 86 percent of
/// its bytes in place (28.8 MiB of 32, 228 of 256, 1,724 of 2,048) and
/// lent the rest, so most of the hash ran while the decode's delivery
/// stood still. A stream whose feeder is away at least half as long as
/// the hash holds it gathers its feeds and LENDS them instead, at a copy
/// a byte, and the hash runs beside the decode.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[derive(Clone, Copy, Default)]
struct Feeder {
    /// The stream gathers and lends every feed from here on. It does not
    /// turn back while the team takes its stages: the rule is read until
    /// it says lend, and never again.
    gathers: bool,
    /// The team refused a stage: this stream hashes in place to its end,
    /// so a stream never goes to and fro.
    refused: bool,
    placed: usize,
    busy: std::time::Duration,
    away: std::time::Duration,
    /// When the last in-place feed returned to its caller; and, while the
    /// stream is `unproved`, when its last feed of any kind did.
    left_at: Option<std::time::Instant>,
    /// This member began gathering on the verdict of the member before it
    /// through the same hasher. See [`Blake2sp::unsustain`].
    carried: bool,
    /// A carried member that has not yet shown that ITS feeder is busy:
    /// the question is put at each full stage until it has, or until
    /// [`PROVE_BY`] bytes are gathered.
    unproved: bool,
    /// Bytes an unproved member has gathered, and the time its feeder was
    /// away over them is `away`.
    gathered: usize,
    /// Bytes this member has lent.
    lent_here: usize,
    /// How many times this member has turned to lending: on a verdict
    /// handed to it (counted when it is handed), and by its own timed
    /// rule. Never above [`TURNS_MOST`].
    turns: u8,
    /// What the hash cost the feeding thread when a member of this hasher
    /// last hashed in place: a time over a count of bytes. It is how a
    /// carried member, which hashes nothing in place, says what its
    /// gathered bytes would have held its feeder for.
    rate: (std::time::Duration, usize),
}

/// The most times one member turns to lending: TWICE.
///
/// The whole of a member's life, at its longest: in place; to lending on
/// the verdict handed to it by the member before (one turn, counted when
/// it is handed); back in place when that verdict fails its check by
/// [`PROVE_BY`]; to lending once more by its own timed rule (the second
/// turn); and then it keeps lending. A member that was handed nothing
/// has the one turn of its own rule. Nothing sends a lending member back
/// in place but a failed check, which a member meets once (it is not
/// handed a verdict twice), and a refused stage, which latches it in
/// place to its end. So two is what the rules allow, and the count is
/// held here as well as by them: a member that has turned twice is not
/// turned again whatever its feeds do
/// (`tests::a_member_turns_to_lending_twice_at_the_most`). A turn is a
/// copy of every byte from there on and a change of which thread
/// hashes; it never changes a digest.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const TURNS_MOST: u8 = 2;

/// Bytes a stream hashes in place before it may turn to gathering: two
/// pool thresholds, 1 MiB, so the rule reads two feeds at least.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const PLACED_BEFORE_TURN: usize = 2 * POOL_MIN_BATCH;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl Feeder {
    /// What hashing the bytes an unproved member has gathered would have
    /// held its feeder for, in place, at the rate last measured.
    fn held_for(&self) -> std::time::Duration {
        let (busy, placed) = self.rate;
        busy.mul_f64(self.gathered as f64 / placed.max(1) as f64)
    }
}

/// Bytes a carried member may gather before its feeder must have shown
/// itself busy: four sustained batches, 8 MiB. A decoder delivers in
/// bursts of a few mebibytes with no time between the feeds of one, so a
/// question put inside the first burst reads a busy feeder as a quiet one
/// (counted on a Zen 4, 12 Oct 2026: put once at the first 2 MiB, every
/// second member of a solid chain went back to hashing in place).
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const PROVE_BY: usize = 4 * SUSTAINED_BATCH;

/// The smallest in-place feed a stream times on x86-64: 64 KiB, about
/// thirteen microseconds of hashing against two clock reads. On aarch64
/// every in-place feed is a pool threshold or more and all are timed.
#[cfg(target_arch = "x86_64")]
const TIMED_FEED: usize = POOL_MIN_BATCH / 8;

/// Whether a feeder that was `away` between feeds the hash held it `busy`
/// for is worth lending to: away at least half as long.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn feeder_is_busy(busy: std::time::Duration, away: std::time::Duration) -> bool {
    away * 2 >= busy
}

#[cfg(all(test, any(target_arch = "aarch64", target_arch = "x86_64")))]
thread_local! {
    /// A unit test's answer for [`worth_lending`], on its own thread: `None`
    /// is off (a unit test's timing is the test runner's, not a
    /// stream's), `Some(true)` turns a stream to gathering as soon as it
    /// may whatever its feeder's times.
    static TEST_VERDICT: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Whether a stream with these times turns to gathering and lending.
/// `RARKIT_BLAKE_FEEDER_RULE`, read by a `test-support` build only, forces an
/// arm whatever the times: `0` (or `off`) keeps every stream in place,
/// the arrangement before 12 Oct 2026, and `1` (or `always`) turns every
/// stream that has a team to lend to.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn worth_lending(busy: std::time::Duration, away: std::time::Duration) -> bool {
    #[cfg(test)]
    {
        let _ = (busy, away);
        TEST_VERDICT.with(std::cell::Cell::get) == Some(true)
    }
    #[cfg(not(test))]
    {
        #[cfg(feature = "test-support")]
        {
            static FORCED: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
            let forced = *FORCED.get_or_init(|| {
                let word = std::env::var("RARKIT_BLAKE_FEEDER_RULE").ok()?;
                match word.trim().to_ascii_lowercase().as_str() {
                    "0" | "off" => Some(false),
                    "1" | "always" => Some(true),
                    _ => None,
                }
            });
            if let Some(arm) = forced {
                return arm;
            }
        }
        feeder_is_busy(busy, away)
    }
}

/// The most input a hasher may ever hold back, which is what
/// [`whole_groups`] leaves behind: a whole group when the input ends on
/// a group boundary, and a group plus the partial one otherwise.
const HOLD: usize = 2 * GROUP;

/// Input the streaming hasher stages before it calls the kernel, and the
/// whole of its working memory: **525,312 bytes**, one heap block per
/// hasher, whatever the input size and whatever the chunking.
///
/// It is [`POOL_MIN_BATCH`] plus [`HOLD`], and that is the whole of the
/// choice. [`flush`] hands the kernel every staged group that no leaf can
/// have its last block in, which is `held - HOLD`; for that to clear the
/// carried team's pool threshold on a full stage, the stage must be the
/// threshold plus the hold and not the threshold itself. Spec L 3.3.2
/// sets only the FLOOR (one block per leaf, so up to `HOLD` bytes, must
/// wait for `finalize`) and spec L 7 only the ceiling (peak RSS no higher
/// than the old engine's, which is 69.7 MB on a 64 MiB input); this is
/// 0.76 percent of that ceiling, and is the size of the old engine's own
/// hasher buffer, which is the same constant for the same reason.
///
/// [`flush`]: Blake2sp::flush
const BUFFER: usize = POOL_MIN_BATCH + HOLD;

// The pairing the whole arrangement rests on, checked where a change to
// the CARRIED kernel's threshold would break it: at compile time, not in
// a test that might not be run.
const _: () = {
    assert!(
        BUFFER.is_multiple_of(GROUP),
        "the whole stage is dispatchable"
    );
    assert!(
        BUFFER >= POOL_MIN_BATCH + HOLD,
        "a full flush must clear the pool threshold"
    );
    // The WARM in-place arm has no such floor to keep and must not be
    // given one: the kernel is chosen by then, and a run under the pool
    // threshold runs at width one behind the seam rather than waking a
    // pool, so the only thing a larger figure here would buy is the
    // memcpy this arm exists to avoid.
    assert!(
        ABSORB_MIN_BATCH <= POOL_MIN_BATCH,
        "the in-place threshold is never above the stage's own"
    );
    assert!(
        ABSORB_MIN_BATCH.is_multiple_of(GROUP),
        "every batch is whole groups"
    );
};

/// The batch a SUSTAINED stream lends the team: four of the pool
/// threshold, 2 MiB. A lent batch is a hand-over to every worker and a
/// wait for them all at the next one, and that cost is per batch whatever
/// its size, so a stream long enough to have shown itself pays a quarter
/// as many of them.
///
/// **Why 2 MiB.** Counted twice on an M1 Ultra (20 cores, one plain
/// release binary, the knob below, K=5, 12 Oct 2026), wall of the 512 KiB
/// arrangement over the arm. While only a fifth of a decoded member's
/// bytes were lent (before [`Feeder`]), `t` and `x` of a 2 GiB binary
/// member at `-m3`: 1 MiB 1.025 and 1.024, 2 MiB 1.021 and 1.020, 4 MiB
/// 1.015 and 1.014, 16 MiB 1.007. With a busy feeder's stream gathering
/// every feed, where the batch carries the whole member: `t` of 2 GiB,
/// 256 MiB and 32 MiB members 1.224, 1.207 and 1.099 at 1 MiB; 1.305,
/// 1.276 and 1.158 at 2 MiB; 1.316, 1.289 and 1.131 at 4 MiB; 1.319,
/// 1.289 and 1.083 at 8 MiB. The peak over the in-place arrangement is 1
/// to 3 MiB at 2 MiB, 7 to 10 at 4 MiB and 15 to 18 at 8 MiB.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const SUSTAINED_BATCH: usize = 4 * POOL_MIN_BATCH;

/// The stage a sustained stream gathers into: [`SUSTAINED_BATCH`] plus the
/// hold, for the reason [`BUFFER`] is the pool threshold plus the hold.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const SUSTAINED_STAGE: usize = SUSTAINED_BATCH + HOLD;

/// What a lending stream holds in stages at the very most: two of
/// [`SUSTAINED_STAGE`] and never a third, **4,196,352 bytes**, where a
/// stream that never lends holds the one stage of [`BUFFER`] bytes
/// (525,312). One stage is being gathered into while the other is in
/// flight; the shorter stage a stream began with is let go before the
/// longer is taken. A hasher keeps the pair from member to member while
/// its members hand their verdict on, so a chain takes it once, and lets
/// it go when one does not (see [`PAIRS_MOST`]).
///
/// **This figure is charged to no working memory account** (the hasher
/// charges nothing to `crate::memory`, its one stage included, so none of
/// it shows in the peak a read reports); it is held inside the process
/// headroom instead, and BOUNDED so that it can be:
/// [`MemoryPolicy::PROCESS_HEADROOM`](crate::MemoryPolicy::PROCESS_HEADROOM)
/// is what a process holds beside engine working memory. A hasher that
/// holds the longer pair holds [`LENDING_OVER`] bytes, 3,671,040, over
/// the in-place arrangement, and at most [`PAIRS_MOST`] hashers of a
/// process hold it at once, so the most a process holds for lending is
/// 7,342,080 bytes: under the headroom, and under the 9 MiB that
/// constant's own comment says it has to spare over what was counted.
/// `tests::the_longer_pairs_of_a_process_stay_under_the_headroom` holds
/// it.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const LENDING_STAGES: usize = 2 * SUSTAINED_STAGE;

/// What a hasher that holds the longer pair holds over one that hashes
/// in place: 3,671,040 bytes.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const LENDING_OVER: usize = LENDING_STAGES - BUFFER;

/// The most hashers of a process that hold the longer pair of stages at
/// once: TWO.
///
/// **Why there is a ceiling.** A hasher keeps the pair it grew, from
/// member to member, so that a chain takes it once; and a process may
/// hold many hashers (a read holds one an operation and one a pool
/// worker), each of which may have lent at some time. Without a ceiling
/// the bytes held would be the count of hashers that ever lent times
/// [`LENDING_OVER`], which nothing bounds. With it they are
/// `PAIRS_MOST * LENDING_OVER` at the very most.
///
/// **Why two.** One lending stream is the shipped case: the census
/// (`share`) gives the whole allowance to a stream that hashes alone.
/// Two leaves room for a second (a stream that began alone and is still
/// running when another begins alone) and keeps the bytes inside what the
/// headroom has to spare. A hasher that would grow and finds no place
/// keeps the two stages of [`BUFFER`] bytes and lends them as they are,
/// batches of the pool threshold: it loses the quarter as many
/// hand-overs, never a digest. A hasher gives its place back, and frees
/// the longer pair, when a member of it ends and hands no verdict on,
/// when a member drops the verdict handed to it at its first byte, and
/// when it is dropped.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const PAIRS_MOST: usize = 2;

/// The most a relayed feed is cut to: one stage, 2 MiB, the read path's
/// own piece on `x` of a large stored member. Counted on an M5 Max, 16 Oct
/// 2026: with no join per feed the read size stops mattering from 2 MiB up
/// (`x` and `t` level from 2 to 16 MiB), and only the stages grow with it.
#[cfg(target_arch = "aarch64")]
const RELAY_STAGE: usize = SUSTAINED_BATCH;

/// Stages a relaying hasher holds: one for each feed the relay may have
/// queued and one to copy the next into, 6 MiB in all. Never more: a stage
/// is reused once every share is past it, and the relay has at most
/// `RELAY_DEPTH` queued whenever this thread copies.
#[cfg(target_arch = "aarch64")]
const RELAY_STAGES: usize = crate::carry::h_ours::rar50::blake2sp::many::RELAY_DEPTH + 1;

/// The most hashers of a process that hold relay stages at once: TWO, as
/// [`PAIRS_MOST`] and for its reasons. The census gives the whole allowance,
/// which the relay needs, to a stream that hashes alone. A hasher with no
/// place hashes in place, as before the relay.
#[cfg(target_arch = "aarch64")]
const RELAYS_MOST: usize = 2;

#[cfg(all(not(test), target_arch = "aarch64"))]
static RELAYS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(test, target_arch = "aarch64"))]
thread_local! {
    static RELAYS_HERE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Feeds this thread's hashers have RELAYED.
    static RELAYED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A place under [`RELAYS_MOST`] for one more hasher, or `false`.
#[cfg(target_arch = "aarch64")]
fn relay_claimed() -> bool {
    #[cfg(not(test))]
    {
        use std::sync::atomic::Ordering::Relaxed;
        RELAYS
            .fetch_update(Relaxed, Relaxed, |n| (n < RELAYS_MOST).then_some(n + 1))
            .is_ok()
    }
    #[cfg(test)]
    RELAYS_HERE.with(|n| {
        let free = n.get() < RELAYS_MOST;
        if free {
            n.set(n.get() + 1);
        }
        free
    })
}

/// Give a place under [`RELAYS_MOST`] back.
#[cfg(target_arch = "aarch64")]
fn relay_given_back() {
    #[cfg(not(test))]
    RELAYS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    RELAYS_HERE.with(|n| n.set(n.get() - 1));
}

/// Hashers of this process holding the longer pair. Per THREAD under
/// `cfg(test)`, as the stream census is and for the same reason.
#[cfg(all(not(test), any(target_arch = "aarch64", target_arch = "x86_64")))]
static PAIRS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(test, any(target_arch = "aarch64", target_arch = "x86_64")))]
thread_local! {
    static PAIRS_HERE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A place under [`PAIRS_MOST`] for one more hasher, or `false`.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn pair_claimed() -> bool {
    #[cfg(not(test))]
    {
        use std::sync::atomic::Ordering::Relaxed;
        PAIRS
            .fetch_update(Relaxed, Relaxed, |n| (n < PAIRS_MOST).then_some(n + 1))
            .is_ok()
    }
    #[cfg(test)]
    PAIRS_HERE.with(|n| {
        let free = n.get() < PAIRS_MOST;
        if free {
            n.set(n.get() + 1);
        }
        free
    })
}

/// Count one more holder whatever the ceiling: a clone's.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn pair_counted() {
    #[cfg(not(test))]
    PAIRS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    PAIRS_HERE.with(|n| n.set(n.get() + 1));
}

/// Give a place under [`PAIRS_MOST`] back.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn pair_given_back() {
    #[cfg(not(test))]
    PAIRS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    PAIRS_HERE.with(|n| n.set(n.get() - 1));
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const _: () = assert!(
    LENDING_STAGES == 4_196_352
        && LENDING_OVER == 3_671_040
        && PAIRS_MOST * LENDING_OVER == 7_342_080,
    "the figures the comments state"
);

/// Bytes a stream has LENT before it is sustained and its stages grow: 4
/// MiB, eight stages. A member shorter than this keeps the two stages of
/// [`BUFFER`] bytes and nothing else, so only a stream that is still
/// lending past this figure holds the larger pair.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const SUSTAINED_AFTER: usize = 8 * POOL_MIN_BATCH;

/// `RARKIT_BLAKE_SUSTAINED`: `0` (or `off`) keeps every lent stage at
/// [`BUFFER`], the arrangement before 12 Oct 2026; a count from 2 to 64
/// is the sustained batch in pool thresholds (4 is [`SUSTAINED_BATCH`]),
/// a measuring arm; anything else, or nothing, is [`SUSTAINED_BATCH`]. A
/// RUNTIME knob, so one binary carries every arm. It moves how much is
/// lent at once, never a digest. On aarch64 and x86-64 only: elsewhere
/// nothing is lent.
///
/// Read behind `test-support`, which a bench build turns on and no
/// shipped build does: a shipped build reads no environment word, and its
/// sustained stage is [`SUSTAINED_STAGE`].
#[cfg(all(
    any(target_arch = "aarch64", target_arch = "x86_64"),
    any(test, feature = "test-support")
))]
pub(crate) const BLAKE_SUSTAINED_ENV: &str = "RARKIT_BLAKE_SUSTAINED";

#[cfg(all(test, any(target_arch = "aarch64", target_arch = "x86_64")))]
thread_local! {
    /// A unit test's answer for [`sustains`], on its own thread.
    static SUSTAINED_HERE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// [`BLAKE_SUSTAINED_ENV`]'s value as the stage a sustained stream
/// gathers into, or `None` where its stages do not grow.
#[cfg(all(
    any(target_arch = "aarch64", target_arch = "x86_64"),
    any(test, feature = "test-support")
))]
fn sustained_of(value: Option<&str>) -> Option<usize> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("0" | "off") => None,
        Some(word) => match word.parse::<usize>() {
            Ok(n @ 2..=64) => Some(n * POOL_MIN_BATCH + HOLD),
            _ => Some(SUSTAINED_STAGE),
        },
        None => Some(SUSTAINED_STAGE),
    }
}

/// The stage a sustained stream gathers into, or `None` where its stages
/// do not grow: a unit test's answer on its own thread; then, in a
/// `test-support` build, the environment's, read once; and
/// [`SUSTAINED_STAGE`] in every other build.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn sustained_stage() -> Option<usize> {
    #[cfg(test)]
    if let Some(forced) = SUSTAINED_HERE.with(std::cell::Cell::get) {
        return forced.then_some(SUSTAINED_STAGE);
    }
    #[cfg(feature = "test-support")]
    {
        static STAGE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        *STAGE.get_or_init(|| sustained_of(std::env::var(BLAKE_SUSTAINED_ENV).ok().as_deref()))
    }
    #[cfg(not(feature = "test-support"))]
    Some(SUSTAINED_STAGE)
}

// How many batches this thread has handed the kernel, how large the FIRST
// of them was, and the SMALLEST of them. Test-only instrumentation, and a
// `Cell` of three words
// rather than a list because `a_short_member_never_builds_a_team` counts
// every byte the allocator hands out and a growing list would be one.
//
// The first batch is the one property a test cannot read any other way:
// it is what chooses the kernel, the choice is made once and can never be
// remade, so a first batch under the pool threshold pins a whole stream
// to one worker with nothing visible from outside but the wall.
#[cfg(test)]
thread_local! {
    static BATCHES: std::cell::Cell<(usize, usize, usize)> =
        const { std::cell::Cell::new((0, 0, usize::MAX)) };
    // The worker allowance the last hasher built on this thread was given.
    // Test-only, and it exists because the one thing spec L's leaf team
    // needed was REACHABILITY: the team was built, tested and correct, and
    // every shipped read and write path asked for one worker, so no caller
    // could ever meet it. Nothing in any output says which allowance a
    // hasher holds, so a test of the wiring has to read it here.
    static ALLOWANCE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    // Stages this thread's hashers have LENT to the kernel.
    static LENDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One batch of `len` bytes, folded into [`BATCHES`]'s running triple.
#[cfg(test)]
fn seen_batch(
    (count, first, smallest): (usize, usize, usize),
    len: usize,
) -> (usize, usize, usize) {
    (
        count + 1,
        if count == 0 { len } else { first },
        smallest.min(len),
    )
}

/// The worker allowance the last hasher built on this thread was given,
/// and a way to forget it first. See [`ALLOWANCE`].
#[cfg(test)]
pub(crate) fn last_allowance() -> usize {
    ALLOWANCE.with(|seen| seen.get())
}

#[cfg(test)]
pub(crate) fn forget_allowance() {
    ALLOWANCE.with(|seen| seen.set(0));
}

/// What a reader arms a member's hasher with: the worker allowance, and
/// beside it the WIDTH the read resolved for that member.
///
/// They are two figures because the allowance is not the width: the read
/// path gives the larger of the memory policy's worker figure and the
/// width, which under the tool's default policy is 7 at a stated width of
/// one. The allowance sizes the team; the width is what the caller named,
/// and a named width is a promise (see [`Blake2sp::arm`]).
///
/// A caller with one figure has given both: `Armed::from(workers)` is
/// that allowance at that width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Armed {
    /// The worker allowance, as [`Blake2sp::with_workers`] takes it.
    pub(crate) workers: usize,
    /// The width the read resolved for this member; zero reads as one.
    pub(crate) width: usize,
}

impl From<usize> for Armed {
    fn from(workers: usize) -> Armed {
        Armed {
            workers,
            width: workers,
        }
    }
}

/// An incremental BLAKE2sp.
///
/// # Working memory
///
/// [`BUFFER`] bytes - 525,312 - in ONE heap block taken at construction,
/// and nothing else at any point in any chunking. Whatever the caller
/// feeds is absorbed where it lies once it is worth the kernel on its
/// own; only the tail that no leaf may compress yet, and feeds too small
/// to be worth a call, are copied here. So `update` never costs a second
/// copy of the input, and the peak this entry point adds to a process is
/// a constant. The block is `alloc_zeroed`, so a hasher over a short
/// member faults in the pages it writes and no more.
#[cfg_attr(
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
    derive(Clone)
)]
pub(crate) struct Blake2sp {
    /// Built on the FIRST batch, not here: which kernel a batch is worth
    /// is a question the first one answers and a constructor cannot.
    /// See [`Blake2sp::dispatch`].
    leaves: Option<Leaves>,
    /// The most recent `held` bytes of the stream, not yet compressed.
    /// [`BUFFER`] bytes long, always, and never shared: it is only ever
    /// LENT whole, and a new stage takes its place first (see
    /// [`Blake2sp::lend_stage`]).
    stage: Stage,
    /// The second stage of a stream that lends its full stages to the
    /// team, when it is not the one in flight: taken at a stream's first
    /// lend and kept across `reset`, so a hasher reused member after
    /// member takes it once. `None` for every hasher that never lends,
    /// which is every one below a team of eight.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    spare: Option<Lent>,
    /// How much this stream gathers before a full stage is handed over:
    /// [`BUFFER`], and [`SUSTAINED_STAGE`] once the stream is sustained
    /// and the stage it gathers into is that long (see
    /// [`Blake2sp::lend_stage`]).
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    limit: usize,
    /// Bytes this stream has lent the team so far, which is what makes it
    /// sustained.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    lent: usize,
    /// This hasher holds a place under [`PAIRS_MOST`], and so may hold
    /// the longer pair of stages. A stage longer than [`BUFFER`] is never
    /// in a hasher's hands without it.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    paired: bool,
    /// What this stream knows of its feeding thread. See [`Feeder`].
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    feeder: Feeder,
    held: usize,
    workers: usize,
    /// The width the read resolved for the member in hand
    /// ([`Armed::width`]), at least one. At a width of one the lend
    /// forms add no thread and no turn: see [`Blake2sp::forms_apply`].
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    width: usize,
    /// The member in hand is STORED, by the read path's word
    /// ([`Blake2sp::arm_member`]). Neither lend form touches such a
    /// member: see [`Blake2sp::forms_apply`].
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    stored: bool,
    /// The stages a stored member's feeds are copied into and relayed from
    /// (see [`Blake2sp::relay_feed`]): none until the first relayed feed,
    /// then up to [`RELAY_STAGES`], kept for the hasher's life.
    #[cfg(target_arch = "aarch64")]
    relay_stages: Vec<Lent>,
    /// Their bytes, charged to the working memory of the operation that
    /// took them for as long as they are held.
    #[cfg(target_arch = "aarch64")]
    relay_charge: crate::memory::Held,
    /// This hasher holds a place under [`RELAYS_MOST`].
    #[cfg(target_arch = "aarch64")]
    relay_place: bool,
    /// This hasher counted in the stream census, from its first byte until it is
    /// finished or reset.
    stream: Option<Stream>,
    /// The allowance THIS stream hashes at, [`shared`] out of `workers`
    /// when its first batch chose the kernel; `workers` until then.
    chosen: usize,
    /// Bytes of the caller's input this hasher has COPIED into the stage,
    /// which is the whole of what a chunked feed costs over a one-shot
    /// one. Kept only under test, where
    /// `a_long_chunked_feed_is_absorbed_where_it_lies` holds it to a
    /// constant per call rather than to a share of the input.
    #[cfg(test)]
    copied: usize,
}

/// A stage of [`BUFFER`] zeroed bytes, `alloc_zeroed` so a short member
/// faults in only the pages it writes.
fn fresh_stage() -> Stage {
    let stage = vec![0u8; BUFFER].into_boxed_slice();
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    let stage = Lent::new(stage);
    stage
}

/// A stage of `len` zeroed bytes, for a stream whose stages have grown.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn stage_of(len: usize) -> Stage {
    Lent::new(vec![0u8; len].into_boxed_slice())
}

/// The stage's type. On aarch64 a full stage may be LENT to the team, so it
/// is shared through an `Arc` for the flight, and on x86-64 it is moved to
/// the helper thread in the same type; everywhere else nothing lends (the
/// kernel behind the seam is one thread) and the stage is the control's
/// plain box, so a target the lend cannot help compiles none of it.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
type Stage = Lent;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
type Stage = Box<[u8]>;

/// The stage to write into. Never shared while it is the gathering stage:
/// a stage is lent only after another has taken its place, and a lent one
/// comes back only once its flight is landed and every worker has let go.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn stage_mut(stage: &mut Stage) -> &mut [u8] {
    Lent::get_mut(stage).expect("the gathering stage is never shared")
}

/// Where nothing lends the stage is never shared: the control's plain box.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn stage_mut(stage: &mut Stage) -> &mut [u8] {
    stage
}

/// A clone is a second stream over the same bytes so far. A batch this
/// hasher has lent and not yet landed is waited for and its leaves copied
/// (`carry/wiring.rs`, and `beside` on x86-64); the clone takes a stage of
/// its own and no spare. Where nothing is ever lent the derived clone is
/// the control's.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl Clone for Blake2sp {
    fn clone(&self) -> Blake2sp {
        Blake2sp {
            leaves: self.leaves.clone(),
            stage: Lent::new(Box::<[u8]>::clone(&self.stage)),
            spare: None,
            limit: self.limit,
            lent: self.lent,
            // A clone of a hasher that holds the longer pair holds a
            // stage as long, so it is counted, over the ceiling if it
            // must be: nothing in the read or write path clones one.
            paired: self.paired && {
                pair_counted();
                true
            },
            feeder: self.feeder,
            held: self.held,
            workers: self.workers,
            width: self.width,
            stored: self.stored,
            stream: self.stream.clone(),
            // A clone takes no relay stages: it relays, if at all, on a
            // place and stages of its own.
            #[cfg(target_arch = "aarch64")]
            relay_stages: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            relay_charge: crate::memory::Held::default(),
            #[cfg(target_arch = "aarch64")]
            relay_place: false,
            chosen: self.chosen,
            #[cfg(test)]
            copied: self.copied,
        }
    }
}

/// A hasher that holds the longer pair gives its place back as it goes.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl Drop for Blake2sp {
    fn drop(&mut self) {
        if self.paired {
            pair_given_back();
        }
        // The leaves land any relayed run before the stages go.
        #[cfg(target_arch = "aarch64")]
        if self.relay_place {
            self.leaves = None;
            self.relay_stages.clear();
            relay_given_back();
        }
    }
}

impl Blake2sp {
    /// A hasher over no bytes yet, on the calling thread.
    ///
    /// Reached from this crate's tests and from the `internals_l` seam;
    /// the shipped read and write paths each have the operation's worker
    /// ceiling to pass and take [`with_workers`] (API 8.2).
    ///
    /// [`with_workers`]: Blake2sp::with_workers
    #[allow(dead_code)]
    pub(crate) fn new() -> Blake2sp {
        Blake2sp::with_workers(1)
    }

    /// A hasher allowed `workers` threads. One (or none) is [`new`].
    ///
    /// [`new`]: Blake2sp::new
    pub(crate) fn with_workers(workers: usize) -> Blake2sp {
        let allowed = Self::allowed(workers);
        // The count word is read here, before any member: see
        // `counts_printed`.
        #[cfg(feature = "test-support")]
        let _ = counts_printed();
        Self {
            leaves: None,
            stage: fresh_stage(),
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            spare: None,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            limit: BUFFER,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            lent: 0,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            paired: false,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            feeder: Feeder::default(),
            held: 0,
            workers: allowed,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            width: allowed,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            stored: false,
            stream: None,
            #[cfg(target_arch = "aarch64")]
            relay_stages: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            relay_charge: crate::memory::Held::default(),
            #[cfg(target_arch = "aarch64")]
            relay_place: false,
            chosen: allowed,
            #[cfg(test)]
            copied: 0,
        }
    }

    /// The allowance a hasher holds for a caller's `workers`.
    fn allowed(workers: usize) -> usize {
        // Without the `parallel` feature there is one thread to allow,
        // whatever the caller asked for; with it, an allowance of zero
        // still means this thread. The figure is HELD rather than acted on
        // here, because the carried team reads the allowance the hasher was
        // built with and `lanes` reads the one for the batch in hand.
        #[cfg(feature = "f8x16-probe")]
        let workers = match TEAM_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
            0 => workers,
            forced => forced,
        };
        let allowed = if cfg!(feature = "parallel") {
            workers.max(1)
        } else {
            1
        };
        #[cfg(test)]
        ALLOWANCE.with(|seen| seen.set(allowed));
        allowed
    }

    /// [`reset`] for a member allowed `workers` threads: the read path's
    /// one hasher is started again for each member that carries a digest,
    /// and a pool worker's members are not all given one width.
    ///
    ///
    /// The read path arms with [`arm`], which carries the width too; this
    /// is the one figure form, reached from this module's tests.
    ///
    /// [`reset`]: Blake2sp::reset
    /// [`arm`]: Blake2sp::arm
    #[allow(dead_code)]
    pub(crate) fn reset_for(&mut self, workers: usize) {
        self.arm(Armed::from(workers));
    }

    /// [`reset_for`] with the member's width beside its allowance: what
    /// the read path arms its one hasher with for each member that
    /// carries a digest.
    ///
    /// **A named width of one is one thread at work.** A member armed at
    /// a width of one is hashed at an allowance of ONE, whatever the
    /// allowance beside it: it builds no team, and the lanes run on the
    /// calling thread, as they always did on x86-64. The read path's
    /// allowance at a stated width of one is 7 under the tool's default
    /// policy (the larger of the memory policy's figure and the width),
    /// and a team built at it put three leaf threads to work beside the
    /// walk: counted on an M1 Ultra, 15 Oct 2026, `x -mt1` of one stored
    /// 4 GiB member read 3.00 CPU over wall where the help promises one
    /// worker thread. A wider width keeps its allowance, so the default
    /// width does not move
    /// (`tests::a_member_read_at_a_width_of_one_hashes_on_the_calling_thread`).
    ///
    /// [`reset_for`]: Blake2sp::reset_for
    pub(crate) fn arm(&mut self, armed: Armed) {
        let workers = if armed.width <= 1 { 1 } else { armed.workers };
        self.workers = Self::allowed(workers);
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            self.width = armed.width.max(1);
            self.stored = false;
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let _ = armed.width;
        self.reset();
    }

    /// [`arm`] for a member the read path knows the method of: `stored`
    /// says the member's bytes are in the archive as they are, so nothing
    /// decodes them. It is the member's own, as its width is: the next
    /// member through this hasher is armed afresh.
    ///
    /// [`arm`]: Blake2sp::arm
    pub(crate) fn arm_member(&mut self, armed: Armed, stored: bool) {
        self.arm(armed);
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            self.stored = stored;
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let _ = stored;
    }

    /// Start again over no bytes, keeping the stage this hasher already
    /// owns.
    ///
    /// [`new`] is not free any more: the stage is a heap block now (see the
    /// module comment), so a caller that hashes many things in a row and
    /// builds a hasher for each pays an allocation for each. The read
    /// path is exactly that caller - one member after another, each with
    /// its own BLAKE2sp - and API promise 2.4 forbids it an allocation per
    /// member, so it holds ONE hasher and resets it here.
    ///
    /// Nothing but the stage survives: the leaves are dropped, so the next
    /// batch builds them again, and `held` is zeroed, so no byte of the
    /// old stage is ever read. The digest is the digest of what follows
    /// this call and nothing before it, which
    /// `tests::a_reset_hasher_gives_the_digest_a_fresh_one_does` holds.
    ///
    /// [`new`]: Blake2sp::new
    pub(crate) fn reset(&mut self) {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        self.keep_spare();
        self.leaves = None;
        self.held = 0;
        self.unsustain();
        self.stream = None;
        self.chosen = self.workers;
        #[cfg(test)]
        {
            self.copied = 0;
        }
    }

    /// How much this stream gathers before a full stage is handed over.
    /// Where nothing is lent it is [`BUFFER`], always.
    #[inline]
    fn limit(&self) -> usize {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        return self.limit;
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        return BUFFER;
    }

    /// A member is over. The next stream through this hasher has lent
    /// nothing and gathers [`BUFFER`] at a time, whatever length of stage
    /// the last one left, UNLESS the member that just ended was lending
    /// on its feeder's verdict: then the next one is handed that verdict.
    ///
    /// **Why a verdict is handed on.** Every member used to begin from
    /// nothing, and that is most of a short one. Counted on an M1 Ultra,
    /// 12 Oct 2026, on solid chains of 32 members (the shipped pair of
    /// the form against main): a member paid about 3.0 MiB hashed in
    /// place before the rule could turn, 0.9 MiB staged and never lent,
    /// and its first 4 MiB of lent bytes in 512 KiB batches. So a chain
    /// of 8 MiB members lent 4.3 of each 8 MiB and read 1.01, a chain of
    /// 16 MiB members 1.11 to 1.14, of 32 MiB members 1.20 to 1.25, where
    /// one member of 256 MiB read 1.31. A hasher is reused member after
    /// member by ONE feeder (the operation's hasher on a solid chain), so
    /// the member after a lending one begins gathering at once, into the
    /// stages the hasher already holds.
    ///
    /// **And it is checked.** A handed verdict is the last member's and
    /// not this one's (a stored member's wide read may follow a decoded
    /// one), so a carried member is `unproved` at first: at each full
    /// stage its feeder's time away over the bytes gathered is put to the
    /// same rule, against what hashing those bytes in place would have
    /// held the feeder for at the rate last measured. Once the feeder
    /// shows itself busy the question is closed. A feeder that has not by
    /// [`PROVE_BY`] sends the stream back to the ordinary rule (in place
    /// and timed, free to turn on its own measure), at the cost of that
    /// much copied; it is never handed a verdict twice. A member that
    /// ends before it lends anything, or ends unproved with a feeder its
    /// own feeds read as quiet, hands nothing on.
    #[inline]
    fn unsustain(&mut self) {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            let last = self.feeder;
            // A verdict already handed on, to a member that has not fed a
            // byte, stands: the read path finishes one member and then
            // starts the hasher again for the next (`reset_for`).
            if last.unproved && last.gathered == 0 {
                return;
            }
            self.feeder = Feeder::default();
            // A member that ended still unproved hands on only what its
            // own feeds showed.
            let shown = !last.unproved || worth_lending(last.held_for(), last.away);
            if last.gathers && last.lent_here > 0 && shown {
                self.feeder.gathers = true;
                self.feeder.carried = true;
                self.feeder.unproved = true;
                self.feeder.turns = 1;
                self.feeder.rate = if last.placed > 0 {
                    (last.busy, last.placed)
                } else {
                    last.rate
                };
            } else {
                self.limit = BUFFER;
                self.lent = 0;
                self.unpair();
            }
        }
    }

    /// Free the longer pair and give its place back, at a point where the
    /// stage holds no byte and nothing is in flight: a member has ended
    /// and hands nothing on, or drops what it was handed at its first
    /// byte. See [`PAIRS_MOST`].
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn unpair(&mut self) {
        if !self.paired {
            return;
        }
        debug_assert_eq!(self.held, 0, "the stage is empty where it is let go");
        // Each longer stage is let go BEFORE the shorter takes its place,
        // so letting the pair go never holds more than the pair.
        if self
            .spare
            .as_ref()
            .is_some_and(|spare| spare.len() > BUFFER)
        {
            self.spare = None;
        }
        if self.stage.len() > BUFFER {
            self.stage = Lent::new(Box::default());
            self.stage = fresh_stage();
        }
        self.paired = false;
        pair_given_back();
    }

    /// Whether this stream gathers and lends a feed it could hash in
    /// place. Where nothing lends it never does.
    #[inline]
    fn stages_every_feed(&self) -> bool {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        return self.feeder.gathers;
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        return false;
    }

    /// Whether the lend forms apply to the member in hand: they do not at
    /// a width of one, and they do not to a stored member.
    ///
    /// **A named width is a promise.** A caller who asks for one thread
    /// gets one thread working: the feeder rule would hand such a member's
    /// hash to a helper thread (x86-64) or move it off the feeding thread
    /// onto the team (aarch64), a second thread at work beside the decode
    /// that the width did not allow. The allowance cannot say so, because
    /// the read path gives the larger of the memory policy's figure and
    /// the width, 7 at a stated width of one under the tool's default
    /// policy; so the read path passes the width too ([`Armed`]).
    ///
    /// At a width of one the forms therefore add NO THREAD AND NO TURN:
    /// the member's feeds are not timed (no clock is read), the feeder
    /// rule never turns it, it takes no verdict from the member before it
    /// and hands none on, and on x86-64, where only a turned stream
    /// lends, it takes no helper thread.
    ///
    /// Nor does a member at a width of one have a team to lend a stage
    /// to: [`Blake2sp::arm`] gives it an allowance of one, so its lanes
    /// run on the calling thread and nothing of it is lent at all. (Until
    /// 15 Oct 2026 it was given the read path's allowance, 7 at a stated
    /// width of one, and on aarch64 its small feeds' stages were lent to
    /// the team that built, the longer stages once 4 MiB were lent: `t`
    /// of one 2 GiB member at one thread read 1.03 of main for it,
    /// counted on an M1 Ultra, 13 Oct 2026. That gain went with the team,
    /// for the promise the width makes.)
    ///
    /// **A stored member never turns.** The forms move a member's hash
    /// off the thread its decoder delivers on, so the two run side by
    /// side. A stored member has no decode: there is nothing for its hash
    /// to run beside, and a turn is then a copy of every byte for no
    /// gain. Counted on a Zen 4, 13 Oct 2026, plain builds: of sixteen
    /// stored members of 256 MiB read at once one turned and lent 254 MB
    /// of 4,295, and the row read 0.92 of what it read with neither
    /// form; with no stored member turning it read 1.00, and sixteen
    /// compressed members at once did not move. So a member the read
    /// path arms as stored ([`Blake2sp::arm_member`]) is hashed as a
    /// member at a width of one is, at every width: not timed, never
    /// turned, handed nothing and handing nothing on
    /// (`tests::a_stored_member_never_turns_and_a_compressed_one_still_may`).
    /// The gate is the member's own: a compressed member through the
    /// same hasher, and a stream that began beside others and widens
    /// late, turn as ever.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[inline]
    fn forms_apply(&self) -> bool {
        self.width > 1 && !self.stored
    }

    /// Whether an in-place feed of `len` bytes is timed for the feeder
    /// rule: a warm one of a member the forms apply to. On x86-64 a feed
    /// of a few groups is taken in place, and a clock read is a share of
    /// hashing one, so only a feed of `TIMED_FEED` or more is timed.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[inline]
    fn timed(&self, warm: bool, len: usize) -> bool {
        #[cfg(target_arch = "x86_64")]
        let worth = len >= TIMED_FEED;
        #[cfg(target_arch = "aarch64")]
        let worth = {
            let _ = len;
            true
        };
        warm && worth && self.forms_apply()
    }

    /// A feed has arrived: the time since the last in-place feed returned
    /// is time its feeder was away.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[inline]
    fn feeder_arrives(&mut self) {
        if let Some(left) = self.feeder.left_at.take() {
            self.feeder.away += left.elapsed();
        }
    }

    /// An in-place feed of `take` bytes that began at `began` is hashed:
    /// keep its times, and turn the stream to gathering where its feeder
    /// is busy and the team takes lent stages.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn feeder_waited(&mut self, began: std::time::Instant, take: usize) {
        let now = std::time::Instant::now();
        let feeder = &mut self.feeder;
        feeder.busy += now - began;
        feeder.placed = feeder.placed.saturating_add(take);
        feeder.left_at = Some(now);
        if feeder.placed >= PLACED_BEFORE_TURN
            && !feeder.refused
            && feeder.turns < TURNS_MOST
            && worth_lending(feeder.busy, feeder.away)
            && self
                .leaves
                .as_ref()
                .is_some_and(|leaves| leaves.will_lend(POOL_MIN_BATCH))
        {
            feeder.gathers = true;
            feeder.left_at = None;
            feeder.turns = feeder.turns.saturating_add(1);
        }
    }

    /// Hand the kernel one batch of whole groups, none of which is any
    /// leaf's last.
    ///
    /// **The batch that BUILDS a team is at least [`POOL_MIN_BATCH`], and
    /// a smaller one that reaches a built team runs on the calling
    /// thread.** The carried team builds its resident pool on the first
    /// batch that size and opened a `std::thread::scope` of its own for
    /// every batch that arrived before it - seven `pthread_create`s and
    /// about 2,700 bytes it never frees, per call. Three things together
    /// make that unreachable from here rather than merely unlikely: the
    /// stage is sized so that every batch flushed from it clears the
    /// threshold; the team is not BUILT until a batch that clears it
    /// arrives WITH more work behind it - see [`Blake2sp::finalize`],
    /// which chooses the calling thread whatever it is holding; and the
    /// seam runs a batch under the threshold at width one, which is what
    /// the short aligning run of [`Blake2sp::update`]'s in-place path
    /// takes. A hasher whose input never fills the stage therefore never
    /// owns a team at all and finishes in package L's own lane kernel,
    /// which is the right arrangement for it anyway.
    ///
    /// The kernel can only be chosen once, and the first batch is the only
    /// moment at which choosing is free: no leaf has absorbed a byte yet,
    /// so no state has to move.
    ///
    /// A free function over two fields rather than a method, because every
    /// caller dispatches out of `self.stage` and would otherwise hold
    /// `self` borrowed twice.
    fn dispatch(leaves: &mut Option<Leaves>, chosen: &mut usize, ceiling: usize, groups: &[u8]) {
        if groups.is_empty() {
            return;
        }
        debug_assert_eq!(groups.len() % GROUP, 0, "whole groups only");
        #[cfg(test)]
        BATCHES.with(|seen| seen.set(seen_batch(seen.get(), groups.len())));
        choose(leaves, chosen, ceiling);
        let workers = *chosen;
        let leaves = leaves.get_or_insert_with(|| {
            Leaves::with_workers(if groups.len() >= POOL_MIN_BATCH {
                workers
            } else {
                1
            })
        });
        leaves.absorb(groups, team(groups.len(), workers));
    }

    /// Hand the kernel the bytes still STAGED and the caller's own, as ONE
    /// batch of two pieces hashed as if they were concatenated.
    ///
    /// The staged run is at most a group of alignment plus the hold - about
    /// a kilobyte - and it has to precede the caller's bytes in stream
    /// order. Dispatched on its own it was a second call through the seam
    /// on every `update`, for a scrap of work: counted, a 16 MiB feed at
    /// 525,312 bytes a call made 62 batches where it now makes 31.
    ///
    /// **It was NOT a barrier on the caller's pool, and the distinction is
    /// worth keeping.** The seam sizes width by the batch in front of it,
    /// so the scrap ran at width one and the carried kernel hashed it on
    /// the calling thread: no pool was woken, no leaf was waited on, and
    /// nothing about it grew with the width the caller brought. So the old
    /// arrangement did not breach SPEC-API 8.3, whose rule is that a stage
    /// may not put the caller's pool under a barrier at a fine grain and
    /// that an operation's wall never rises with pool width. What it was
    /// is WASTE: a dispatch and a pass through the seam bought nothing.
    ///
    /// What carrying the scrap adds is that 8.3's property is now
    /// STRUCTURAL rather than incidental. The width is decided by the
    /// TOTAL, so nothing under the kernel's worthwhile size reaches the
    /// kernel at all, and a later change to the seam's width rule cannot
    /// quietly turn these scraps into pool wakes.
    ///
    /// Both pieces are non-empty whole groups by construction - the stage
    /// is topped up to a group boundary before this is called, and
    /// [`whole_groups`] gives the caller's share - and neither can hold any
    /// leaf's last block, because a `HOLD` of the stream is left behind.
    fn dispatch_pieces(
        leaves: &mut Option<Leaves>,
        chosen: &mut usize,
        ceiling: usize,
        staged: &[u8],
        groups: &[u8],
    ) {
        debug_assert_eq!(staged.len() % GROUP, 0, "whole groups only");
        debug_assert_eq!(groups.len() % GROUP, 0, "whole groups only");
        debug_assert!(!staged.is_empty(), "the staged piece is never empty here");
        debug_assert!(!groups.is_empty(), "the caller's piece is never empty here");
        let total = staged.len() + groups.len();
        #[cfg(test)]
        BATCHES.with(|seen| seen.set(seen_batch(seen.get(), total)));
        choose(leaves, chosen, ceiling);
        let workers = *chosen;
        let leaves = leaves.get_or_insert_with(|| {
            Leaves::with_workers(if total >= POOL_MIN_BATCH { workers } else { 1 })
        });
        leaves.absorb_pieces(&[staged, groups], team(total, workers));
    }

    /// Feed `data`. Any chunking gives the same digest.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if self.stream.is_none() && !data.is_empty() {
            self.stream = Some(Stream::enter());
            // A handed verdict is dropped at once by a member nothing
            // would lend for (one allowed too few workers, or one that
            // shares the machine with other streams): it would only
            // gather a stage to have it refused. And by a member read at
            // a width of one, which the forms give no thread and no turn.
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            if self.feeder.unproved && (!self.forms_apply() || shared(self.workers) <= SHARED_TEAM)
            {
                self.feeder = Feeder::default();
                self.limit = BUFFER;
                self.lent = 0;
                self.unpair();
            }
        }
        // A feed worth the kernel on its own is absorbed WHERE IT LIES:
        // nothing of it is copied but the tail no leaf may compress yet.
        // This is the whole of what a chunked caller costs over a one-shot
        // one, so the gate below is as low as each side can bear rather
        // than as high as the simplest arrangement wants.
        //
        // Anything already staged has to go first, because the stream
        // keeps its order, and it has to reach the kernel as WHOLE GROUPS.
        // How it is made whole is the difference between the two states:
        //
        // - **before a kernel is chosen**, the stage is topped up to
        //   `BUFFER` and handed over whole, so the FIRST batch is
        //   `POOL_MIN_BATCH` and a team is built at the width the caller
        //   allowed. Choosing on a smaller first batch pins the whole
        //   stream to one worker, which was
        //   measured the hard way: the leg became the `-1w` leg;
        // - **afterwards**, the stage is topped up to the next GROUP
        //   boundary only - at most 511 bytes - and that short run is
        //   handed over on its own. The kernel is already chosen, so
        //   nothing rests on its size, and `absorb` behind the seam runs a
        //   batch below the pool threshold on the calling thread rather
        //   than waking workers for it.
        //
        // What follows the staged bytes must clear `ABSORB_MIN_BATCH`, the
        // smallest run the kernel on this box wants handed over, with a
        // `HOLD` left behind: more of the stream still follows every batch
        // dispatched here, so none of it can hold any leaf's last block
        // (3.3.2).
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        self.feeder_arrives();
        let warm = self.leaves.is_some();
        let fill = if self.held == 0 {
            0
        } else if warm {
            (GROUP - self.held % GROUP) % GROUP
        } else {
            // A carried member gathers into a longer stage before it has
            // leaves; it gathers every feed then and takes none in place.
            BUFFER.saturating_sub(self.held)
        };
        let min = if warm {
            ABSORB_MIN_BATCH
        } else {
            POOL_MIN_BATCH
        };
        if data.len() >= fill + min + HOLD && !self.stages_every_feed() {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            let began = self.timed(warm, data.len()).then(std::time::Instant::now);
            if self.held > 0 {
                stage_mut(&mut self.stage)[self.held..self.held + fill]
                    .copy_from_slice(&data[..fill]);
                #[cfg(test)]
                {
                    self.copied += fill;
                }
                self.held += fill;
                data = &data[fill..];
            }
            let take = whole_groups(data.len());
            count_bytes(2, take + self.held);
            // A stored member's feed is copied and relayed rather than
            // joined. See `relay_feed`.
            #[cfg(target_arch = "aarch64")]
            let relayed = warm && self.relays() && self.relay_feed(&data[..take]);
            #[cfg(not(target_arch = "aarch64"))]
            let relayed = false;
            if relayed {
                // Every staged and every caller's byte is in the relay.
            } else if self.held > 0 {
                // The staged scrap rides into the caller's batch rather
                // than being dispatched under it. See `dispatch_pieces`.
                Self::dispatch_pieces(
                    &mut self.leaves,
                    &mut self.chosen,
                    self.workers,
                    &self.stage[..self.held],
                    &data[..take],
                );
                self.held = 0;
            } else {
                Self::dispatch(
                    &mut self.leaves,
                    &mut self.chosen,
                    self.workers,
                    &data[..take],
                );
            }
            data = &data[take..];
            debug_assert!(data.len() <= HOLD);
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            if let Some(began) = began {
                self.feeder_waited(began, take);
            }
        }

        // A carried member that has not yet been checked counts what it
        // gathers; its feeder's time away is read as each feed arrives.
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if self.feeder.unproved {
            self.feeder.gathered = self.feeder.gathered.saturating_add(data.len());
        }

        // What is left is at most a buffer and a hold. Stage it, and call
        // the kernel a buffer at a time: a caller that drips bytes in
        // never reaches it with less than `POOL_MIN_BATCH` of them.
        while !data.is_empty() {
            if self.held == self.limit() {
                self.flush(true);
            }
            let take = (self.limit() - self.held).min(data.len());
            stage_mut(&mut self.stage)[self.held..self.held + take].copy_from_slice(&data[..take]);
            #[cfg(test)]
            {
                self.copied += take;
            }
            self.held += take;
            data = &data[take..];
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if self.feeder.unproved {
            self.feeder.left_at = Some(std::time::Instant::now());
        }
    }

    /// Whether this member's in-place feeds are RELAYED: a stored member
    /// (by the read path's word, [`Blake2sp::arm_member`]) at a width
    /// above one, whose team takes a relayed feed (more than two shares),
    /// and a hasher with a place under [`RELAYS_MOST`], taken here at its
    /// first relayed feed and kept for its life.
    ///
    /// **Stored only.** The relay is the in-place arrangement without its
    /// join; a decoded member's feeds are the feeder rule's to place
    /// (`Feeder`), and it was not counted there. **A named width is a
    /// promise:** a member at a width of one hashes at an allowance of one
    /// ([`Blake2sp::arm`]) and has no team, and the width is asked here as
    /// well, so it never relays.
    #[cfg(target_arch = "aarch64")]
    fn relays(&mut self) -> bool {
        if !self.stored || self.width <= 1 || !self.leaves.as_ref().is_some_and(Leaves::will_relay)
        {
            return false;
        }
        if !self.relay_place {
            self.relay_place = relay_claimed();
        }
        self.relay_place
    }

    /// Copy the staged groups and then `groups` into stages of this
    /// hasher's own, at most [`RELAY_STAGE`] each, and RELAY each to the
    /// team: no feed is joined. `true` once every byte is handed over;
    /// the staged scrap is then empty.
    ///
    /// **Why.** A stored member's feeds clear the in-place threshold and
    /// were hashed where they lay, each a dispatch the feeding thread
    /// waited on until the slowest share was done, so every feed paid for
    /// the spread between the shares and the wake of the team. Counted on
    /// an M5 Max, 16 Oct 2026, one stored 4 GiB member under BLAKE2sp at
    /// the default width, plain builds, a loaded laptop: `x` 0.89 s to
    /// about 0.70 and `t` 0.85 to 0.64 (measured together), user CPU level, at
    /// the cost of this copy. The caller's bytes cannot be relayed where
    /// they lie: `update`'s borrow ends at its return, and the relay
    /// needs them until the slowest share is past them. A shared buffer of
    /// the caller's own was counted too and lost on `t`, the relay hashing
    /// a reader's buffer 13 to 15 percent slower than its own stage.
    ///
    /// The digest is the in-place one by construction: the same groups in
    /// the same order, each feed starting from the leaf counter the last
    /// ended at, every leaf's last block still held back by the caller's
    /// `HOLD`.
    #[cfg(target_arch = "aarch64")]
    fn relay_feed(&mut self, groups: &[u8]) -> bool {
        debug_assert_eq!(self.held % GROUP, 0, "the scrap is whole groups here");
        let total = self.held + groups.len();
        let mut at = 0;
        while at < total {
            let len = (total - at).min(RELAY_STAGE);
            let Some(index) = self.free_relay_stage() else {
                // Unreachable while the relay keeps its depth: a stage is
                // free whenever this thread copies. Kept correct anyway:
                // the rest in place, after the relayed run.
                if at == 0 {
                    return false;
                }
                self.absorb_rest(groups, at, total);
                return true;
            };
            let stage = Lent::get_mut(&mut self.relay_stages[index]).expect("a free stage");
            let staged = self.held.saturating_sub(at).min(len);
            if staged > 0 {
                stage[..staged].copy_from_slice(&self.stage[at..at + staged]);
            }
            let from = at + staged - self.held;
            stage[staged..len].copy_from_slice(&groups[from..from + len - staged]);
            let lent = Lent::clone(&self.relay_stages[index]);
            let leaves = self.leaves.as_mut().expect("a relayed feed has leaves");
            if let Err(lent) = leaves.relay(lent, len) {
                if at == 0 {
                    // Nothing is out: the caller hashes the feed in place.
                    return false;
                }
                // The team's threads would not start: what is copied is
                // hashed here, the rest in place, in order.
                leaves.absorb(&lent[..len], team(len, self.chosen));
                drop(lent);
                self.absorb_rest(groups, at + len, total);
                self.held = 0;
                return true;
            }
            #[cfg(test)]
            RELAYED.with(|n| n.set(n.get() + 1));
            at += len;
        }
        self.held = 0;
        true
    }

    /// A relay stage no share holds any more, made if fewer than
    /// [`RELAY_STAGES`] exist; `None` only if every one is still out.
    #[cfg(target_arch = "aarch64")]
    fn free_relay_stage(&mut self) -> Option<usize> {
        if let Some(index) = self
            .relay_stages
            .iter_mut()
            .position(|stage| Lent::get_mut(stage).is_some())
        {
            return Some(index);
        }
        if self.relay_stages.len() >= RELAY_STAGES {
            return None;
        }
        self.relay_stages.push(stage_of(RELAY_STAGE));
        self.relay_charge
            .set((self.relay_stages.len() * RELAY_STAGE) as u64);
        Some(self.relay_stages.len() - 1)
    }

    /// Hash bytes `at..total` of the staged groups followed by `groups`
    /// in place, after whatever is relayed (the kernel lands it first).
    #[cfg(target_arch = "aarch64")]
    fn absorb_rest(&mut self, groups: &[u8], at: usize, total: usize) {
        let staged = self.held.saturating_sub(at);
        let leaves = self.leaves.as_mut().expect("a relayed feed has leaves");
        if staged > 0 {
            leaves.absorb(&self.stage[at..self.held], team(staged, self.chosen));
        }
        let from = at + staged - self.held;
        if from < total - self.held {
            let rest = &groups[from..];
            leaves.absorb(rest, team(rest.len(), self.chosen));
        }
        self.held = 0;
    }

    /// Absorb every staged group that no leaf can have its last block in,
    /// and shift the rest to the front. Leaves at most [`HOLD`] staged.
    ///
    /// On a full stage this is exactly [`POOL_MIN_BATCH`], which is what
    /// [`BUFFER`] is sized for. The one call that can be shorter is
    /// `finalize`'s, which is the last one the hasher ever makes.
    ///
    /// With `lend`, a stage the kernel will take whole is LENT to it rather
    /// than hashed while this thread waits (see [`Self::lend_stage`]).
    /// `finalize` does not lend: it would only wait at once.
    fn flush(&mut self, lend: bool) {
        let take = whole_groups(self.held);
        if take == 0 {
            return;
        }
        // A carried member's check, at each full stage until it is
        // settled: is ITS feeder busy? See `unsustain`. One that has not
        // shown it by `PROVE_BY` is an ordinary stream again from here: in
        // place, timed, `BUFFER` at a time, and free to turn on its own
        // measure as any stream is.
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if lend && self.feeder.unproved {
            let feeder = &mut self.feeder;
            if worth_lending(feeder.held_for(), feeder.away) {
                feeder.unproved = false;
                feeder.left_at = None;
            } else if feeder.gathered >= PROVE_BY {
                *feeder = Feeder {
                    carried: true,
                    rate: feeder.rate,
                    turns: feeder.turns,
                    ..Feeder::default()
                };
                self.limit = BUFFER;
                self.lent = 0;
            }
        }
        // On x86-64 only a stream the feeder rule turned lends: a stream
        // of feeds too small to take in place is hashed as it always was.
        #[cfg(target_arch = "x86_64")]
        let lend = lend && self.feeder.gathers;
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if lend {
            if self.lend_stage(take) {
                return;
            }
            // Nothing takes a lent stage after all: in place from here
            // to the stream's end.
            if self.feeder.gathers {
                self.feeder.gathers = false;
                self.feeder.refused = true;
                if self.feeder.carried {
                    self.limit = BUFFER;
                    self.lent = 0;
                }
            }
        }
        count_bytes(1, take);
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let _ = lend;
        Self::dispatch(
            &mut self.leaves,
            &mut self.chosen,
            self.workers,
            &self.stage[..take],
        );
        stage_mut(&mut self.stage).copy_within(take..self.held, 0);
        self.held -= take;
    }

    /// Lend the first `take` bytes of the stage to the kernel and gather
    /// on into the second stage meanwhile; `false`, with nothing changed,
    /// where the kernel takes no lent batch (a team of two or less, or a
    /// stream that has not earned one).
    ///
    /// **This is the chunked rows' serial stage taken off the calling
    /// thread.** A caller feeding runs under the in-place threshold has
    /// every byte gathered here, and each full stage used to be hashed
    /// while this thread waited, the gather and the hash one after the
    /// other with seven workers idle for the whole of the gather. Lent,
    /// the batch is hashed by one worker per share while this thread copies
    /// the caller's next runs into the other stage, and the two meet only
    /// when that stage is full in turn: the chunked wall is then the larger
    /// of the gather and the hash rather than their sum.
    ///
    /// The cost is the second stage, [`BUFFER`] bytes taken at a stream's
    /// first lend and kept for the hasher's life, which is spec L 7's
    /// working memory plus 513 KiB on a stream at a team of eight and
    /// nothing on any other.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn lend_stage(&mut self, take: usize) -> bool {
        // Before `will_lend` is asked, so the answer is for the figure the
        // batch will be lent at; a flight still in the air was started at
        // its own width and is landed by `settle` below before the next.
        choose(&mut self.leaves, &mut self.chosen, self.workers);
        let workers = self.chosen;
        let leaves = self.leaves.get_or_insert_with(|| {
            Leaves::with_workers(if take >= POOL_MIN_BATCH { workers } else { 1 })
        });
        if !leaves.will_lend(take) {
            return false;
        }
        #[cfg(test)]
        BATCHES.with(|seen| seen.set(seen_batch(seen.get(), take)));
        // The stage to gather into next: the one the last flight used, back
        // from the kernel now it is landed, or the spare, or a new one at a
        // stream's first lend.
        //
        // A SUSTAINED stream gathers into a stage of `SUSTAINED_STAGE`
        // from here on: a shorter one that comes back is let go BEFORE the
        // longer is taken, so the stream holds two stages at any moment
        // and never three. Both are kept for the hasher's life, so a
        // hasher reused member after member takes the longer pair once.
        // And only a hasher with a place under `PAIRS_MOST` grows: one
        // without keeps lending the two stages of `BUFFER` bytes.
        let want = match sustained_stage() {
            Some(longer) if self.lent >= SUSTAINED_AFTER => {
                if !self.paired {
                    self.paired = pair_claimed();
                }
                if self.paired {
                    longer
                } else {
                    BUFFER
                }
            }
            _ => BUFFER,
        };
        let mut next = leaves
            .settle()
            .or_else(|| self.spare.take())
            .filter(|stage| stage.len() >= want)
            .unwrap_or_else(|| stage_of(want));
        let rest = self.held - take;
        stage_mut(&mut next)[..rest].copy_from_slice(&self.stage[take..self.held]);
        let full = std::mem::replace(&mut self.stage, next);
        match leaves.lend(full, take) {
            Ok(()) => {
                #[cfg(test)]
                LENDS.with(|n| n.set(n.get() + 1));
                self.held = rest;
                self.lent = self.lent.saturating_add(take);
                self.feeder.lent_here = self.feeder.lent_here.saturating_add(take);
                count_bytes(0, take);
                // `next` is at least `want` long, and may be longer where
                // an earlier member of this hasher grew it: the limit is
                // the stream's own, not the stage's.
                self.limit = want;
                true
            }
            Err(full) => {
                // The kernel could not start its workers after all: the
                // stage is handed back untouched, and absorbed in place.
                self.spare = Some(std::mem::replace(&mut self.stage, full));
                let leaves = self.leaves.as_mut().expect("chosen just above");
                leaves.absorb(&self.stage[..take], team(take, workers));
                stage_mut(&mut self.stage).copy_within(take..self.held, 0);
                self.held = rest;
                // The stage that came back may be the shorter one.
                self.limit = want.min(self.stage.len());
                true
            }
        }
    }

    /// Land whatever this hasher has lent and keep its stage as the spare.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn keep_spare(&mut self) {
        if let Some(stage) = self.leaves.as_mut().and_then(Leaves::settle) {
            self.spare = Some(stage);
        }
    }

    /// The digest of everything fed.
    /// The digest of everything fed so far, leaving the hasher ready for
    /// the next thing over no bytes and keeping its stage.
    ///
    /// [`finalize`] consumes, which a caller holding ONE hasher for many
    /// members cannot afford: cloning to finalize copies the stage, and
    /// that is an allocation per member (API promise 2.4). The two agree
    /// by construction - `finalize` is this with the hasher dropped
    /// afterwards.
    ///
    /// [`finalize`]: Blake2sp::finalize
    pub(crate) fn finalize_reset(&mut self) -> [u8; DIGEST] {
        self.leaves.get_or_insert_with(|| Leaves::with_workers(1));
        self.flush(false);
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        self.keep_spare();
        let leaves = self.leaves.take().expect("chosen just above");
        let digest = leaves.finish(&self.stage[..self.held]);
        #[cfg(feature = "test-support")]
        if counts_printed() {
            let get = |i: usize| COUNT_BYTES[i].swap(0, std::sync::atomic::Ordering::Relaxed);
            // And how many times the member that just ended turned to
            // lending, for the rows of a solid chain.
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            let turns = self.feeder.turns;
            #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
            let turns = 0u8;
            eprintln!(
                "BLAKECOUNT lent {} staged-unlent {} in-place {} turns {}",
                get(0),
                get(1),
                get(2),
                turns
            );
        }
        self.held = 0;
        self.unsustain();
        self.stream = None;
        self.chosen = self.workers;
        digest
    }

    /// The digest of everything fed, consuming the hasher. Reached from
    /// the `internals_l` seam and from tests; the write path holds one
    /// hasher for every member and takes [`finalize_reset`].
    ///
    /// [`finalize_reset`]: Blake2sp::finalize_reset
    #[allow(dead_code)]
    pub(crate) fn finalize(mut self) -> [u8; DIGEST] {
        // One body for both, so a hasher taken by value and one finished
        // in place cannot drift apart. What the comment on
        // `finalize_reset` says about the calling thread and the pool
        // holds here too.
        self.finalize_reset()
    }
}

#[cfg(test)]
mod tests {
    use super::lanes::{BLOCK, LEAVES};
    use super::*;

    /// BLAKE2s from RFC 7693 section 3, with the full parameter block of
    /// section 2.8, as an independent reference for the crate kernel.
    mod rfc7693 {
        const IV: [u32; 8] = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
            0x5BE0CD19,
        ];
        const SIGMA: [[usize; 16]; 10] = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
            [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
            [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
            [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
            [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
            [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
            [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
            [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
            [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        ];

        fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }

        fn compress(h: &mut [u32; 8], block: &[u8; 64], counter: u64, last: bool, last_node: bool) {
            let m: [u32; 16] = std::array::from_fn(|i| {
                u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap())
            });
            let mut v = [0u32; 16];
            v[..8].copy_from_slice(h);
            v[8..].copy_from_slice(&IV);
            v[12] ^= counter as u32;
            v[13] ^= (counter >> 32) as u32;
            if last {
                v[14] = !v[14];
            }
            if last_node {
                v[15] = !v[15];
            }
            for s in &SIGMA {
                g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
            }
            for i in 0..8 {
                h[i] ^= v[i] ^ v[i + 8];
            }
        }

        /// One BLAKE2s over `message` with the tree parameters spec L
        /// 3.3.1 names.
        pub(super) fn blake2s(
            message: &[u8],
            node_offset: u64,
            node_depth: u8,
            last_node: bool,
        ) -> [u8; 32] {
            // Parameter block: digest 32, key 0, fanout 8, depth 2, leaf
            // length 0, node offset (6 bytes), node depth, inner 32.
            let mut param = [0u8; 32];
            param[0] = 32;
            param[1] = 0;
            param[2] = 8;
            param[3] = 2;
            param[8..14].copy_from_slice(&node_offset.to_le_bytes()[..6]);
            param[14] = node_depth;
            param[15] = 32;
            let mut h = IV;
            for i in 0..8 {
                h[i] ^= u32::from_le_bytes(param[4 * i..4 * i + 4].try_into().unwrap());
            }
            let mut counter = 0u64;
            let mut rest = message;
            while rest.len() > 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&rest[..64]);
                counter += 64;
                compress(&mut h, &block, counter, false, false);
                rest = &rest[64..];
            }
            let mut block = [0u8; 64];
            block[..rest.len()].copy_from_slice(rest);
            counter += rest.len() as u64;
            compress(&mut h, &block, counter, true, last_node);
            let mut out = [0u8; 32];
            for i in 0..8 {
                out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_le_bytes());
            }
            out
        }
    }

    /// BLAKE2sp exactly as spec L 3.3.1 states it, one leaf at a time.
    fn reference(data: &[u8]) -> [u8; 32] {
        let mut leaf_input = vec![Vec::new(); LEAVES];
        for (b, block) in data.chunks(BLOCK).enumerate() {
            leaf_input[b % LEAVES].extend_from_slice(block);
        }
        let mut message = Vec::with_capacity(LEAVES * DIGEST);
        for (index, input) in leaf_input.iter().enumerate() {
            message.extend_from_slice(&rfc7693::blake2s(
                input,
                index as u64,
                0,
                index == LEAVES - 1,
            ));
        }
        rfc7693::blake2s(&message, 0, 1, true)
    }

    fn filler(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    /// The share rule on its own: a lone stream keeps whatever it was
    /// allowed, and a stream beside others takes at most the shared team,
    /// never more than it was allowed.
    #[test]
    fn a_shared_stream_takes_the_shared_team_and_a_lone_one_keeps_its_allowance() {
        for workers in [1usize, 2, 3, 4, 8, 32] {
            assert_eq!(share(workers, 0), workers);
            assert_eq!(share(workers, 1), workers);
            for live in [2usize, 3, 8, 64] {
                assert_eq!(
                    share(workers, live),
                    workers.min(SHARED_TEAM),
                    "{workers} {live}"
                );
            }
        }
    }

    /// The census end to end, on ONE thread (the census is per thread
    /// under test, so no other test's streams reach it): what each stream
    /// CHOSE at its first batch, and that every digest is the one-worker
    /// digest whichever team hashed it.
    ///
    /// The eight-member rows are exactly the second case: eight streams
    /// live at once, each of which used to build a team of eight.
    #[test]
    fn a_stream_beside_another_builds_the_shared_team_and_a_lone_one_the_whole_one() {
        let data = filler(BUFFER * 3 + 1000);
        let want = blake2sp(&data);
        assert_eq!(live_streams(), 0, "nothing live before the test");

        // Alone: the whole allowance.
        let mut alone = Blake2sp::with_workers(8);
        alone.update(&data);
        assert_eq!(alone.chosen, 8);
        assert_eq!(live_streams(), 1);
        assert_eq!(alone.finalize_reset(), want);
        assert_eq!(live_streams(), 0, "finishing leaves the census");

        // Beside another: the shared team, and the other is only counted
        // once it has taken a byte.
        let mut neighbour = Blake2sp::with_workers(8);
        let mut beside = Blake2sp::with_workers(8);
        beside.update(&data[..BUFFER]);
        assert_eq!(beside.chosen, 8, "a hasher with no bytes is not a stream");
        beside.reset();
        neighbour.update(&data[..1]);
        beside.update(&data);
        assert_eq!(beside.chosen, SHARED_TEAM);
        assert_eq!(beside.finalize_reset(), want);
        let mut rest = neighbour.clone();
        assert_eq!(live_streams(), 2, "a clone is a stream of its own");
        rest.update(&data[1..]);
        assert_eq!(rest.finalize(), want);
        // The clone has finished, so the neighbour chooses ALONE: the
        // census is read when the kernel is chosen, not when the hasher
        // was built.
        neighbour.update(&data[1..]);
        assert_eq!(neighbour.chosen, 8);
        drop(neighbour);
        assert_eq!(live_streams(), 0, "a dropped hasher leaves the census");

        // The one-shot entry counts too, and is the same digest.
        let mut other = Blake2sp::with_workers(8);
        other.update(&data[..1]);
        assert_eq!(blake2sp_with_workers(&data, 8), want);
        other.reset();
        assert_eq!(live_streams(), 0, "a reset leaves the census");

        // And the reused hasher, the read path's own shape: alone again,
        // whole again.
        alone.update(&data);
        assert_eq!(alone.chosen, 8);
        assert_eq!(alone.finalize_reset(), want);
    }

    /// Run `f` with the re-share forced `on` for this thread's streams.
    #[cfg(target_arch = "aarch64")]
    fn resharing<T>(on: bool, f: impl FnOnce() -> T) -> T {
        RESHARE_HERE.with(|r| r.set(Some(on)));
        let out = f();
        RESHARE_HERE.with(|r| r.set(None));
        out
    }

    /// `RARKIT_BLAKE_RESHARE`'s words, and that it ships on.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_reshare_knob_reads_its_words_and_ships_on() {
        const { assert!(RESHARE) };
        assert!(reshare_of(None));
        assert!(reshare_of(Some("1")));
        assert!(reshare_of(Some(" ON ")));
        assert!(!reshare_of(Some("0")));
        assert!(!reshare_of(Some("off")));
        assert!(reshare_of(Some("what")));
    }

    /// The re-share end to end, on ONE thread: a stream that began beside
    /// a neighbour takes the shared team and WIDENS to its whole allowance
    /// at its next batch once the neighbour has finished; it is NOT
    /// narrowed when another arrives. With the knob off it keeps what its
    /// first batch chose. The digest is the one-worker digest either way.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_stream_widens_when_its_neighbour_finishes_and_is_never_narrowed() {
        let data = filler(BUFFER * 9 + 1000);
        let want = blake2sp(&data);
        let third = BUFFER * 3;
        for on in [false, true] {
            resharing(on, || {
                assert_eq!(live_streams(), 0, "nothing live before the arm");
                let mut neighbour = Blake2sp::with_workers(8);
                neighbour.update(&data[..1]);
                let mut long = Blake2sp::with_workers(8);
                long.update(&data[..third]);
                assert_eq!(long.chosen, SHARED_TEAM, "beside a neighbour");
                neighbour.reset();
                long.update(&data[third..2 * third]);
                let alone = if on { 8 } else { SHARED_TEAM };
                assert_eq!(long.chosen, alone, "alone now");
                neighbour.update(&data[..1]);
                long.update(&data[2 * third..]);
                assert_eq!(long.chosen, alone, "a neighbour arriving narrows nothing");
                assert_eq!(long.finalize_reset(), want, "the digest, knob {on}");
                neighbour.reset();
                assert_eq!(live_streams(), 0);
            });
        }
    }

    /// A stream never widens past the allowance its member was armed
    /// with: the re-share reads the census against `workers`, the ceiling,
    /// and a ceiling of one starts no team at any census.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_reshared_stream_keeps_to_its_members_ceiling() {
        let data = filler(BUFFER * 6 + 77);
        let want = blake2sp(&data);
        resharing(true, || {
            for ceiling in [1usize, 2, 3, 4, 7, 8] {
                let mut neighbour = Blake2sp::with_workers(8);
                neighbour.update(&data[..1]);
                let mut stream = Blake2sp::with_workers(ceiling);
                stream.update(&data[..BUFFER * 2]);
                assert_eq!(stream.chosen, ceiling.min(SHARED_TEAM), "ceiling {ceiling}");
                neighbour.reset();
                stream.update(&data[BUFFER * 2..]);
                assert_eq!(stream.chosen, ceiling, "alone at ceiling {ceiling}");
                assert_eq!(stream.finalize_reset(), want, "ceiling {ceiling}");
                // Started again for the next member, at another ceiling.
                stream.reset_for(2);
                stream.update(&data);
                assert_eq!(stream.chosen, 2);
                assert_eq!(stream.finalize_reset(), want);
            }
        });
    }

    /// The digest is held while the team's width changes between batches,
    /// at every ceiling and for every way a batch reaches the
    /// kernel: whole feeds absorbed where they lie, runs under the
    /// in-place threshold gathered and LENT (a flight started at one width
    /// landed after the width has changed), and a scrap staged in front of
    /// a feed.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_digest_holds_while_the_width_changes_between_batches() {
        let data = filler(BUFFER * 12 + 4321);
        let want = blake2sp(&data);
        resharing(true, || {
            for ceiling in [2usize, 4, 8] {
                for step in [100_000usize, BUFFER - 513, BUFFER + 7, 3 * BUFFER + 11] {
                    let mut neighbour = Blake2sp::with_workers(8);
                    neighbour.update(&data[..1]);
                    let mut stream = Blake2sp::with_workers(ceiling);
                    let mut widths = std::collections::BTreeSet::new();
                    let feeds = data.len().div_ceil(step);
                    for (index, chunk) in data.chunks(step).enumerate() {
                        // The neighbour is alive for the first half of the
                        // feeds and gone after, so the stream starts on
                        // the shared team and widens under way.
                        if index == feeds / 2 {
                            neighbour.reset();
                        }
                        stream.update(chunk);
                        widths.insert(stream.chosen);
                    }
                    assert_eq!(
                        stream.finalize_reset(),
                        want,
                        "ceiling {ceiling} step {step}"
                    );
                    neighbour.reset();
                    if ceiling > SHARED_TEAM {
                        assert!(
                            widths.contains(&ceiling) && widths.contains(&SHARED_TEAM),
                            "ceiling {ceiling} step {step}: both widths ran, saw {widths:?}"
                        );
                    }
                }
            }
        });
    }

    #[test]
    fn empty_input_matches_the_spec() {
        let want = hex("dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f");
        assert_eq!(blake2sp(b""), want);
        assert_eq!(reference(b""), want);
        assert_eq!(Blake2sp::new().finalize(), want);
        assert_eq!(Blake2sp::with_workers(8).finalize(), want);
    }

    /// A third implementation, neither this one nor the RFC transcription
    /// above: `blake2s_simd`'s own BLAKE2sp, which the carry port already
    /// depends on.
    #[test]
    fn kernel_matches_an_independent_crate() {
        for n in [
            0usize,
            1,
            63,
            64,
            65,
            511,
            512,
            513,
            1_023,
            1_024,
            1_025,
            40_000,
            1 << 20,
        ] {
            let data = filler(n);
            assert_eq!(
                blake2sp(&data),
                *blake2s_simd::blake2sp::blake2sp(&data).as_array(),
                "{n}"
            );
        }
    }

    #[test]
    fn kernel_matches_the_definition() {
        for n in [
            0usize, 1, 7, 63, 64, 65, 127, 128, 447, 448, 511, 512, 513, 575, 576, 1023, 1024,
            1025, 1087, 1088, 1535, 1536, 1537, 4096, 4097, 40_000,
        ] {
            let data = filler(n);
            assert_eq!(blake2sp(&data), reference(&data), "one-shot {n}");
        }
    }

    #[test]
    fn every_chunking_and_arrangement_agrees() {
        // A size past the team's batch, so both dispatch arms run.
        let data = filler((8 << 20) + 5_000);
        let want = blake2sp(&data);
        assert_eq!(reference(&data), want);
        for workers in [1usize, 2, 8] {
            for step in [
                1usize,
                3,
                64,
                512,
                513,
                64 << 10,
                256 << 10,
                (512 << 10) - 1,
                512 << 10,
                (512 << 10) + 1,
                BUFFER - 1,
                BUFFER,
                BUFFER + 1,
                1 << 20,
                9 << 20,
            ] {
                let mut hasher = Blake2sp::with_workers(workers);
                for chunk in data.chunks(step) {
                    hasher.update(chunk);
                }
                assert_eq!(hasher.finalize(), want, "workers {workers} step {step}");
            }
        }
    }

    #[test]
    fn pseudo_random_sizes_agree_across_arrangements() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut rand = move |bound: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % bound as u64) as usize
        };
        let big = filler(3 << 20);
        for _ in 0..24 {
            let len = rand(big.len());
            let data = &big[..len];
            let want = reference(data);
            assert_eq!(blake2sp(data), want, "len {len}");
            let mut hasher = Blake2sp::with_workers(4);
            let mut at = 0;
            while at < len {
                let step = (rand(70_000) + 1).min(len - at);
                hasher.update(&data[at..at + step]);
                at += step;
            }
            assert_eq!(hasher.finalize(), want, "len {len} chunked");
        }
    }

    /// Spec L 5.3's nine sizes, which are the ones reference `rar` 7.23's
    /// own `-htb` digests were read at.
    const EDGE_SIZES: [usize; 9] = [0, 1, 64, 511, 512, 513, 4096, 4097, 40_000];

    /// Every arrangement of the streaming hasher, over every chunking of
    /// the nine edge sizes, against the one-shot path AND against the
    /// independent crate.
    #[test]
    fn the_edge_sizes_agree_through_the_streaming_hasher() {
        for n in EDGE_SIZES {
            let data = filler(n);
            let want = *blake2s_simd::blake2sp::blake2sp(&data).as_array();
            assert_eq!(blake2sp(&data), want, "one-shot {n}");
            assert_eq!(reference(&data), want, "definition {n}");
            for workers in [1usize, 2, 8] {
                for step in [
                    1usize,
                    7,
                    63,
                    64,
                    65,
                    511,
                    512,
                    513,
                    4096,
                    64 << 10,
                    256 << 10,
                    (512 << 10) - 1,
                    512 << 10,
                    (512 << 10) + 1,
                ] {
                    let mut hasher = Blake2sp::with_workers(workers);
                    for chunk in data.chunks(step) {
                        hasher.update(chunk);
                    }
                    assert_eq!(hasher.finalize(), want, "{n} workers {workers} step {step}");
                }
            }
        }
    }

    /// Random inputs and random cut points, against the independent crate
    /// and the one-shot path. The sizes straddle the buffer and the team
    /// gate, so both arms of `update` run.
    #[test]
    fn random_chunkings_agree_with_the_independent_crate() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rand = move |bound: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % bound as u64) as usize
        };
        let big = filler((BUFFER * 5) + 12_345);
        for _ in 0..40 {
            let len = rand(big.len());
            let data = &big[..len];
            let want = *blake2s_simd::blake2sp::blake2sp(data).as_array();
            assert_eq!(blake2sp(data), want, "one-shot {len}");
            for workers in [1usize, 8] {
                let mut hasher = Blake2sp::with_workers(workers);
                let mut at = 0;
                while at < len {
                    let step = (rand(BUFFER * 2) + 1).min(len - at);
                    hasher.update(&data[at..at + step]);
                    at += step;
                }
                assert_eq!(hasher.finalize(), want, "{len} workers {workers}");
            }
        }
    }

    /// The streaming hasher's working memory does not scale with the
    /// input, in ANY chunking and at any worker count (spec L 7's
    /// peak-RSS target, SPEC-API section 5 working memory).
    ///
    /// The bound is [`BUFFER`] bytes - 525,312 - which is the one heap
    /// block a hasher takes at construction, plus whatever the chosen
    /// kernel builds once for itself. The pool the carried team builds is
    /// the only such thing and it is far inside the slack below; what the
    /// test is for is that NOTHING here grows with the input.
    ///
    /// History, because the number moved twice. Before 18 Sep 2026 the
    /// hasher accumulated its batch in a `Vec`, which cost a second whole
    /// copy of the input: 136 MB of peak on this 64 MiB buffer, 253 MB
    /// fed in 256 KiB chunks with eight workers allowed, against the old
    /// engine's 69 MB. Absorbing the caller's slice in place cleared
    /// that, but the 64 KiB stage it left behind fed the carried team
    /// batches below its pool threshold, and the team then allocated
    /// about 2,700 bytes per call that it never freed - 689,032 bytes
    /// over a 64 MiB member, 10.8 KiB a MiB, growing without limit on a
    /// large one. The eight-worker chunked arrangement had to be excepted
    /// from this test and pinned in one of its own. It is back in the
    /// list below, and there is no exception left.
    #[test]
    fn the_streaming_hasher_holds_a_constant_however_large_the_input() {
        use crate::rar3_filters::tests::counting;

        let data = filler(64 << 20);
        // Warm the pool: rayon's first `join` builds it, and that
        // allocation is the pool's, not this hasher's.
        {
            let mut warm = Blake2sp::with_workers(8);
            warm.update(&data[..TEAM_MIN_BATCH + BUFFER + GROUP]);
            let _ = warm.finalize();
        }

        let want = blake2sp(&data);
        for (workers, step) in [
            (1usize, None),
            (1, Some(256 << 10)),
            (1, Some(1)),
            (8, None),
            (8, Some(4 << 10)),
            (8, Some(64 << 10)),
            (8, Some(256 << 10)),
            (8, Some(1)),
        ] {
            // One byte at a time over 64 MiB is far too slow to run; the
            // drip case is measured over three buffers, which is where
            // `update` stages rather than absorbing in place.
            let input: &[u8] = match step {
                Some(1) => &data[..BUFFER * 3],
                _ => &data,
            };
            counting::reset_peak();
            let mut hasher = Blake2sp::with_workers(workers);
            match step {
                None => hasher.update(input),
                Some(n) => {
                    for chunk in input.chunks(n) {
                        hasher.update(chunk);
                    }
                }
            }
            let digest = hasher.finalize();
            let peak = counting::peak_bytes();
            // A stream that LENDS its full stages (a staged feed at a team
            // of eight) holds a second stage while one is in flight: one
            // more BUFFER, taken once, the working memory the lent
            // arrangement costs. Every other arrangement holds one.
            // And a stream that lends past `SUSTAINED_AFTER` holds the
            // longer pair instead, never a third stage: still a constant,
            // whatever the input.
            let lends = workers > 1 && step.is_some_and(|n| n < ABSORB_MIN_BATCH);
            #[cfg(target_arch = "aarch64")]
            let lent_stages = 2 * SUSTAINED_STAGE;
            #[cfg(not(target_arch = "aarch64"))]
            let lent_stages = 2 * BUFFER;
            let stages = if lends { lent_stages } else { BUFFER };
            assert!(
                peak <= (stages + (64 << 10)) as u64,
                "workers {workers} step {step:?}: peak {peak} bytes over {} of input",
                input.len()
            );
            if input.len() == data.len() {
                assert_eq!(digest, want, "workers {workers} step {step:?}");
            }
        }

        // The one-shot path was already inside the target; hold it there.
        counting::reset_peak();
        let one_shot = blake2sp(&data);
        let peak = counting::peak_bytes();
        assert_eq!(one_shot, want);
        assert_eq!(peak, 0, "the one-shot path allocates nothing");
    }

    /// Once a hasher has chosen its kernel, feeding it takes NO heap at
    /// all, however many small updates arrive.
    ///
    /// This is the property the 64 KiB stage could not hold, and it is
    /// what `l/blake2sp/chunk256k-8w` cost 0.273x of the old engine for:
    /// under its pool threshold the carried team opened a
    /// `std::thread::scope` per call, which is seven `pthread_create`s
    /// and about 2,700 bytes left behind each time. Ten thousand small
    /// updates would have been 27 MB of it. Now every batch this hasher
    /// dispatches clears the threshold, so the pool is built once and
    /// used for ever after.
    #[test]
    fn small_updates_add_no_heap_once_the_kernel_is_chosen() {
        use crate::rar3_filters::tests::counting;

        const SMALL: usize = 64;
        const UPDATES: usize = 10_000;

        let data = filler(BUFFER * 2 + SMALL * UPDATES);
        let want = blake2sp(&data);

        let mut hasher = Blake2sp::with_workers(8);
        let lead = BUFFER * 2;
        hasher.update(&data[..lead]);
        // Small updates fill the stage and the first full one is LENT,
        // which takes the second stage and starts the team that hashes
        // lent stages. Both are once per stream, so the first stage's worth
        // of small updates is fed before counting.
        let prime = lead + BUFFER + SMALL;
        for chunk in data[lead..prime].chunks(SMALL) {
            hasher.update(chunk);
        }

        // Everything the arrangement ever allocates has happened by here:
        // the stage at construction, the team's pool on the first batch
        // past the threshold, and the second stage and the lending team on
        // the first lent stage.
        counting::reset_peak();
        for chunk in data[prime..].chunks(SMALL) {
            hasher.update(chunk);
        }
        let peak = counting::peak_bytes();
        let digest = hasher.finalize();

        assert_eq!(
            peak, 0,
            "{UPDATES} updates of {SMALL} bytes added {peak} heap bytes"
        );
        assert_eq!(digest, want);
    }

    /// A hasher whose input never fills the stage never builds a team,
    /// whatever the caller allowed.
    ///
    /// Building one would mean seven threads for a single last batch, and
    /// the pool it builds is the only heap either kernel takes, so the
    /// counting allocator sees the difference directly. This is the other
    /// half of what makes the per-call thread start unreachable: the
    /// first batch decides the kernel, and `finalize`'s batch - the only
    /// one that can fall under the threshold - decides for the calling
    /// thread however large it is. `BUFFER - 1` below is the largest
    /// input that reaches the kernel once and only at the end; it staged
    /// 524,288 bytes there, which clears the pool threshold exactly, and
    /// it cost 2,730 bytes of pool before `finalize` stopped consulting
    /// the size.
    #[test]
    fn a_short_member_never_builds_a_team() {
        use crate::rar3_filters::tests::counting;

        for n in [0usize, 1, 512, 40_000, POOL_MIN_BATCH, BUFFER - 1] {
            let data = filler(n);
            let want = blake2sp(&data);
            for step in [None, Some(1024usize)] {
                let mut hasher = Blake2sp::with_workers(8);
                counting::reset_peak();
                match step {
                    None => hasher.update(&data),
                    Some(k) => {
                        for chunk in data.chunks(k) {
                            hasher.update(chunk);
                        }
                    }
                }
                let digest = hasher.finalize();
                let peak = counting::peak_bytes();
                assert_eq!(digest, want, "{n} step {step:?}");
                assert_eq!(peak, 0, "{n} step {step:?}: peak {peak} bytes");
            }
        }
    }

    /// The stage is the carried kernel's pool threshold plus the hold,
    /// and both parts matter: a stage OF the threshold would flush
    /// `POOL_MIN_BATCH - HOLD` and miss it by a hold every time.
    ///
    /// The parts of this that are constant are asserted at compile time
    /// beside [`BUFFER`]; what is here is the part that runs
    /// [`whole_groups`], which is what `flush` and the in-place arm
    /// actually dispatch.
    #[test]
    fn the_stage_is_sized_so_every_flush_clears_the_pool_threshold() {
        assert_eq!(whole_groups(BUFFER), POOL_MIN_BATCH);
        // The COLD in-place arm's batch, which is the one that can build
        // a team: its guard leaves `POOL_MIN_BATCH + HOLD` of the
        // caller's slice behind whatever it flushes first, and
        // `whole_groups` gives back all but the hold of that.
        assert!(whole_groups(POOL_MIN_BATCH + HOLD) >= POOL_MIN_BATCH);
    }

    /// **The chunked path does not copy the stream.** A caller feeding
    /// runs the kernel on this box is willing to take
    /// ([`ABSORB_MIN_BATCH`]) has them absorbed WHERE THEY LIE: what is
    /// copied into the stage is the cold start, plus at most a group of
    /// alignment and the hold per call, and never a share of the input.
    ///
    /// This is the whole of item 1 of the chunked-BLAKE2sp follow-up. The
    /// hasher used to gather every byte of a chunked feed into the stage
    /// before handing it over, which is a second pass over the input that
    /// the one-shot entry point never makes; off aarch64, where the kernel
    /// is one thread with no dispatch to amortise, that copy was the
    /// whole of the chunked legs' shortfall.
    ///
    /// The bound is stated per CALL and the test runs two chunk sizes an
    /// order of magnitude apart, so a copy that came back proportional to
    /// the input would fail at both and a residue that scaled with the
    /// number of calls would fail at the smaller one.
    #[test]
    fn a_long_chunked_feed_is_absorbed_where_it_lies() {
        for step in [ABSORB_MIN_BATCH + HOLD, 8 * (ABSORB_MIN_BATCH + HOLD)] {
            let data = filler(step * 24 + 777);
            let want = blake2sp(&data);
            for workers in [1usize, 8] {
                let mut hasher = Blake2sp::with_workers(workers);
                for chunk in data.chunks(step) {
                    hasher.update(chunk);
                }
                let copied = hasher.copied;
                assert_eq!(hasher.finalize(), want, "step {step} workers {workers}");
                let calls = data.len().div_ceil(step);
                let bound = BUFFER + calls * (GROUP + HOLD);
                assert!(
                    copied <= bound,
                    "step {step} workers {workers}: staged {copied} bytes of {}, bound {bound}",
                    data.len()
                );
            }
        }
    }

    /// The team is still reached by a chunked feed, which is the property
    /// the in-place path above could have broken: the kernel is chosen on
    /// the first batch and can only be chosen once, so a first batch under
    /// [`POOL_MIN_BATCH`] would pin the whole stream to one worker.
    /// Exactly that was measured (the leg
    /// became the `-1w` leg at 0.295x) when the stage was shrunk on its
    /// own.
    ///
    /// Read from outside the way a caller would see it: at eight workers
    /// the digest is right and the hasher is not holding a one-worker
    /// kernel it can never replace.
    #[test]
    fn a_chunked_feed_still_reaches_the_team_at_its_first_dispatch() {
        for step in [ABSORB_MIN_BATCH + HOLD, 256 << 10, BUFFER * 3] {
            let data = filler(BUFFER * 6 + 99);
            let want = blake2sp(&data);
            let mut hasher = Blake2sp::with_workers(8);
            BATCHES.with(|seen| seen.set((0, 0, usize::MAX)));
            for chunk in data.chunks(step) {
                hasher.update(chunk);
            }
            let (count, first, _) = BATCHES.with(|seen| seen.get());
            assert_eq!(hasher.finalize(), want, "step {step}");
            assert!(count > 0, "step {step}: a chunked feed dispatches");
            assert!(
                first >= POOL_MIN_BATCH,
                "step {step}: first batch {first} is under the pool threshold \
                 {POOL_MIN_BATCH}, so the kernel is chosen at one worker for ever"
            );
        }
    }

    /// **No batch under the kernel's worthwhile size ever reaches the
    /// kernel**, and a feed of threshold-sized calls dispatches ONCE per
    /// call.
    ///
    /// SPEC-API 8.3's rule made structural: a stage may not put the
    /// caller's pool under a barrier at a fine grain, and an operation's
    /// wall may not rise with the width of the pool the caller brings.
    ///
    /// Before the scrap was carried, an `update` that absorbed in place
    /// handed over whatever was still staged - at most a group of
    /// alignment plus the hold, about a kilobyte - as a batch of its OWN,
    /// ahead of the caller's bytes. Counted over 16 MiB fed 525,312 bytes
    /// at a time, that was 62 batches with the smallest at 1,024; carried
    /// into the batch it precedes it is 31, and none of them short.
    ///
    /// That old arrangement did not BREACH 8.3: the seam ran those scraps
    /// at width one on the calling thread, so they woke no pool and did
    /// not grow with the caller's width (see
    /// [`Blake2sp::dispatch_pieces`]). They were waste, not a barrier.
    /// What this test is for is that the property stays true by
    /// CONSTRUCTION - no batch under the kernel's worthwhile size is
    /// handed over at all - so a later change to the width rule at the
    /// seam cannot turn a per-call scrap into a per-call pool wake without
    /// failing here first.
    ///
    /// Read BEFORE `finalize`, whose own flush is the one batch that may be
    /// short: it is the last the hasher ever makes, and it runs on the
    /// calling thread by construction (see [`Blake2sp::dispatch`]).
    ///
    /// **The count is read PER CALL, and it was a total until 22 Sep 2026
    /// when the total was found to be an aarch64 reading of an
    /// architecture-dependent rule.** `data.len() / step` counts the
    /// WHOLE-step calls and quietly assumes the short call at the end
    /// dispatches nothing, which is true only where `ABSORB_MIN_BATCH` is
    /// the pool threshold. Off aarch64 it is one group, the trailing
    /// 12,345 bytes are absorbed where they lie, and the total read 5
    /// against 4 on every x86-64 box since the test was written - a
    /// dispatch the seam is right to make, of 12,288 bytes, which is 24
    /// times the worthwhile size this test is named for. See
    /// [`dispatches_expected`].
    /// The batch each `update` of a `data.chunks(step)` feed hands the
    /// kernel, which is ONE for every call that clears the in-place gate
    /// and NONE for a trailing call under it.
    ///
    /// **The gate is [`ABSORB_MIN_BATCH`] and that constant is not the
    /// same on every target, which is why this is computed rather than
    /// written down as `data.len() / step`.** On aarch64 the kernel
    /// behind the seam is a resident team, so the smallest run worth
    /// handing over is the smallest run worth spreading and
    /// `ABSORB_MIN_BATCH` IS [`POOL_MIN_BATCH`]: a short trailing call is
    /// staged whole and dispatches nothing. Off aarch64 the kernel is a
    /// streaming many-way SIMD tree that uses no thread at all, so one
    /// whole group is already worth handing over, `ABSORB_MIN_BATCH` is
    /// one [`GROUP`], and the same trailing call is absorbed WHERE IT
    /// LIES rather than copied into the stage. Both are this module's own
    /// rule read at the same constant, and neither is a dispatch the
    /// kernel did not want.
    ///
    /// Every whole-`step` call clears the gate for every `step` this test
    /// feeds, and each leaves exactly [`HOLD`] staged on a group
    /// boundary, so the fill the gate also asks for is zero and does not
    /// appear here. See [`Blake2sp::update`].
    fn dispatches_expected(len: usize, step: usize) -> Vec<usize> {
        let mut want = vec![1; len / step];
        let rest = len % step;
        if rest > 0 {
            want.push(usize::from(rest >= ABSORB_MIN_BATCH + HOLD));
        }
        want
    }

    #[test]
    fn no_batch_under_the_kernels_worthwhile_size_reaches_it() {
        for step in [BUFFER, BUFFER + GROUP, 1 << 20, 4 << 20] {
            let data = filler(step * 4 + 12_345);
            let want = blake2sp(&data);
            for workers in [1usize, 8] {
                let mut hasher = Blake2sp::with_workers(workers);
                BATCHES.with(|seen| seen.set((0, 0, usize::MAX)));
                // Counted PER CALL rather than in total. The total alone
                // cannot tell a call that dispatched twice from two calls
                // that dispatched once, and the first of those is the
                // thing this test exists to refuse.
                let mut per_call = Vec::new();
                let mut before = 0;
                for chunk in data.chunks(step) {
                    hasher.update(chunk);
                    let count = BATCHES.with(|seen| seen.get()).0;
                    per_call.push(count - before);
                    before = count;
                }
                let (_, _, smallest) = BATCHES.with(|seen| seen.get());
                assert_eq!(hasher.finalize(), want, "step {step} workers {workers}");
                assert!(
                    smallest >= ABSORB_MIN_BATCH,
                    "step {step} workers {workers}: a batch of {smallest} bytes reached \
                     the kernel, under its worthwhile size {ABSORB_MIN_BATCH}"
                );
                assert_eq!(
                    per_call,
                    dispatches_expected(data.len(), step),
                    "step {step} workers {workers}: one dispatch per call that clears \
                     the in-place gate, and none at all under it"
                );
            }
        }
    }

    /// A staged feed at a team of eight LENDS its full stages, and every
    /// chunking still gives the digest: the stream's order is kept although
    /// the calling thread gathers the next stage while the last is hashed.
    /// Held across chunk sizes either side of a group and of the stage, and
    /// at widths that do and do not lend.
    #[test]
    fn a_staged_feed_lends_its_stages_and_keeps_the_digest() {
        let data = filler(BUFFER * 7 + 3 * GROUP + 41);
        let want = blake2sp(&data);
        for step in [1000usize, 4 << 10, 64 << 10, 256 << 10, BUFFER - 1] {
            for workers in [1usize, 2, 4, 8] {
                LENDS.with(|n| n.set(0));
                let mut hasher = Blake2sp::with_workers(workers);
                for chunk in data.chunks(step) {
                    hasher.update(chunk);
                }
                let lent = LENDS.with(std::cell::Cell::get);
                assert_eq!(hasher.finalize(), want, "step {step} workers {workers}");
                let expect = cfg!(target_arch = "aarch64")
                    && workers >= 4
                    && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 8);
                assert_eq!(
                    lent > 0,
                    expect,
                    "step {step} workers {workers}: {lent} lends"
                );
            }
        }
    }

    /// A SUSTAINED staged stream lends the team 2 MiB at a time, not the
    /// 512 KiB a stream begins with: counted over 64 MiB fed 64 KiB a
    /// call at a team of eight, 128 batches before 12 Oct 2026 and 38
    /// with the stages grown (nine of 512 KiB, then 2 MiB each).
    /// The knob-off arm is the arrangement before, in the same binary, and
    /// a stream that never lends keeps the stage it has always had.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_sustained_staged_stream_lends_larger_stages() {
        let data = filler(64 << 20);
        let want = blake2sp(&data);
        // A team of eight is lent to only where one is built: with the
        // `parallel` feature, on a box with a core for every leaf.
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 8);
        for (workers, grows) in [(8usize, true), (8, false), (1, true)] {
            SUSTAINED_HERE.with(|k| k.set(Some(grows)));
            let mut hasher = Blake2sp::with_workers(workers);
            // Past the point a stream is sustained, and one stage more,
            // so every batch counted below is a sustained stream's.
            let lead = SUSTAINED_AFTER + SUSTAINED_STAGE + BUFFER;
            for chunk in data[..lead].chunks(64 << 10) {
                hasher.update(chunk);
            }
            BATCHES.with(|seen| seen.set((0, 0, usize::MAX)));
            for chunk in data[lead..].chunks(64 << 10) {
                hasher.update(chunk);
            }
            let (count, _, smallest) = BATCHES.with(|seen| seen.get());
            assert_eq!(hasher.limit, {
                if wide && workers == 8 && grows {
                    SUSTAINED_STAGE
                } else {
                    BUFFER
                }
            });
            let batch = if wide && workers == 8 && grows {
                SUSTAINED_BATCH
            } else {
                POOL_MIN_BATCH
            };
            assert_eq!(
                smallest, batch,
                "workers {workers} grows {grows}: the smallest of {count} batches"
            );
            assert!(
                count <= (data.len() - lead) / batch,
                "workers {workers} grows {grows}: {count} batches of {batch}"
            );
            // The next member through the same hasher begins again at the
            // stage every stream begins with, and its digest is its own.
            assert_eq!(hasher.finalize_reset(), want, "workers {workers}");
            assert_eq!((hasher.limit, hasher.lent), (BUFFER, 0));
            BATCHES.with(|seen| seen.set((0, 0, usize::MAX)));
            for chunk in data[..BUFFER * 3].chunks(64 << 10) {
                hasher.update(chunk);
            }
            let (_, first, _) = BATCHES.with(|seen| seen.get());
            assert_eq!(first, POOL_MIN_BATCH, "a new member's first batch");
            assert_eq!(
                hasher.finalize_reset(),
                blake2sp(&data[..BUFFER * 3]),
                "workers {workers}: the member after a sustained one"
            );
            SUSTAINED_HERE.with(|k| k.set(None));
        }
    }

    /// A stream whose feeder is busy between feeds stops hashing its
    /// large feeds in place and gathers and lends them, and the digest is
    /// the same either way; a stream with no team to lend to never turns,
    /// and the next member through the hasher begins in place again.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_stream_with_a_busy_feeder_gathers_and_lends_its_large_feeds() {
        use std::time::Duration;
        assert!(feeder_is_busy(
            Duration::from_millis(2),
            Duration::from_millis(1)
        ));
        assert!(!feeder_is_busy(
            Duration::from_millis(2),
            Duration::from_micros(999)
        ));
        assert!(feeder_is_busy(Duration::ZERO, Duration::ZERO));

        let data = filler(48 << 20);
        let want = blake2sp(&data);
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 8);
        // EACH ARM FORCED on the same inputs, always in place and always
        // lent, over sizes either side of the turn and feeds either side
        // of the stage: one digest, whichever thread hashed.
        for len in [(1usize << 20) + 7, (5 << 20) + 1000, 24 << 20] {
            let input = &data[..len];
            let want = reference(input);
            for step in [600 << 10, 2 << 20, (5 << 20) + 13] {
                for arm in [Some(false), Some(true)] {
                    TEST_VERDICT.with(|k| k.set(arm));
                    let mut hasher = Blake2sp::with_workers(8);
                    let mut turned = false;
                    for chunk in input.chunks(step) {
                        hasher.update(chunk);
                        // Once a stream lends it keeps lending.
                        assert!(!turned || hasher.feeder.gathers, "len {len} step {step}");
                        turned = hasher.feeder.gathers;
                    }
                    assert!(arm == Some(true) || !turned, "the in-place arm never turns");
                    assert_eq!(hasher.finalize(), want, "len {len} step {step} arm {arm:?}");
                }
            }
        }
        TEST_VERDICT.with(|k| k.set(None));

        for (workers, forced) in [(8usize, Some(true)), (8, None), (1, Some(true))] {
            TEST_VERDICT.with(|k| k.set(forced));
            LENDS.with(|n| n.set(0));
            let mut hasher = Blake2sp::with_workers(workers);
            for chunk in data.chunks(2 << 20) {
                hasher.update(chunk);
            }
            let turns = wide && workers == 8 && forced == Some(true);
            assert_eq!(hasher.feeder.gathers, turns, "workers {workers} {forced:?}");
            let lent = LENDS.with(std::cell::Cell::get);
            if turns {
                // All but the cold start and the feeds read before the
                // turn went through the stage.
                assert!(lent > 0, "a gathering stream lends");
                assert!(
                    hasher.copied >= data.len() - BUFFER - PLACED_BEFORE_TURN - (4 << 20),
                    "a gathering stream stages its feeds: {} of {}",
                    hasher.copied,
                    data.len()
                );
            } else {
                assert_eq!(lent, 0, "workers {workers} {forced:?}: in place");
                assert!(hasher.copied <= BUFFER + 24 * (GROUP + HOLD));
            }
            assert_eq!(
                hasher.finalize_reset(),
                want,
                "workers {workers} {forced:?}"
            );
            // A member that ended lending hands its verdict on, to be
            // checked once; any other is followed by one in place.
            assert_eq!(hasher.feeder.gathers, turns, "workers {workers} {forced:?}");
            assert_eq!(hasher.feeder.unproved, turns);
            assert_eq!(hasher.feeder.placed, 0);
            TEST_VERDICT.with(|k| k.set(None));
        }
    }

    /// x86-64, where the kernel behind the seam is one thread: EACH ARM
    /// FORCED on the same inputs, always in place and always lent, gives
    /// the one digest (the RFC 7693 reference's), and in the lent arm a
    /// thread other than the feeding one did hash (a stage was lent).
    /// The pool this test assumes is none: the helper is the hasher's own
    /// thread; memory, the 24 MiB input and two stages.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn each_arm_forced_on_x86_64_gives_one_digest_whichever_thread_hashes() {
        let data = filler(24 << 20);
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 2);
        for len in [(1usize << 20) + 7, (5 << 20) + 1000, 24 << 20] {
            let input = &data[..len];
            let want = reference(input);
            for step in [64usize << 10, 600 << 10, 2 << 20, (5 << 20) + 13] {
                for workers in [1usize, 2, 8] {
                    for arm in [Some(false), Some(true)] {
                        TEST_VERDICT.with(|k| k.set(arm));
                        LENDS.with(|n| n.set(0));
                        let mut hasher = Blake2sp::with_workers(workers);
                        for chunk in input.chunks(step) {
                            hasher.update(chunk);
                        }
                        let lent = LENDS.with(std::cell::Cell::get);
                        assert_eq!(
                            hasher.finalize(),
                            want,
                            "len {len} step {step} workers {workers} arm {arm:?}"
                        );
                        // A long stream of feeds the rule can time turns
                        // and lends where it is forced to and has a helper
                        // to lend to; nothing else lends at all.
                        let long = len == 24 << 20 && step <= 2 << 20;
                        if arm == Some(true) && wide && workers == 8 && long {
                            assert!(lent > 0, "len {len} step {step}: the lent arm lends");
                        }
                        if arm == Some(false) || workers <= 2 || !wide {
                            assert_eq!(lent, 0, "len {len} step {step} workers {workers}");
                        }
                    }
                }
            }
        }
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// x86-64: a stream that lends keeps lending, the next member through
    /// the hasher begins in place again, and a hasher with a stage out on
    /// the helper thread can be cloned, reset, finished or dropped, each
    /// giving what a hasher that never lent gives. No pool is assumed;
    /// memory, the 24 MiB input and two stages.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_lending_stream_on_x86_64_keeps_lending_and_clones_resets_and_drops() {
        let data = filler(24 << 20);
        let want = reference(&data);
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 2);
        let cut = (9 << 20) + 4096;
        let feed = |hasher: &mut Blake2sp, bytes: &[u8], step: usize| {
            let mut turned = hasher.feeder.gathers;
            for chunk in bytes.chunks(step) {
                hasher.update(chunk);
                assert!(
                    !turned || hasher.feeder.gathers,
                    "a stream never turns back"
                );
                turned = hasher.feeder.gathers;
            }
        };
        TEST_VERDICT.with(|k| k.set(Some(true)));
        LENDS.with(|n| n.set(0));
        let mut hasher = Blake2sp::with_workers(8);
        feed(&mut hasher, &data[..cut], 256 << 10);
        assert_eq!(
            hasher.feeder.gathers, wide,
            "a forced stream turns where it can lend"
        );
        assert_eq!(LENDS.with(std::cell::Cell::get) > 0, wide);
        // The stages grew once the stream was sustained: one constant.
        assert_eq!(hasher.limit, if wide { SUSTAINED_STAGE } else { BUFFER });
        // A clone mid-flight, finished on its own.
        let mut clone = hasher.clone();
        feed(&mut clone, &data[cut..], 1 << 20);
        assert_eq!(clone.finalize(), want, "the clone");
        // The original, carried on after its clone was taken.
        feed(&mut hasher, &data[cut..], 300 << 10);
        assert_eq!(hasher.finalize_reset(), want, "the original");
        // It ended lending, so the next member is handed its verdict and
        // the stages it grew; elsewhere the next member begins in place.
        assert_eq!(hasher.feeder.gathers, wide);
        assert_eq!(hasher.feeder.unproved, wide);
        assert_eq!(hasher.feeder.placed, 0);
        assert_eq!(hasher.limit, if wide { SUSTAINED_STAGE } else { BUFFER });
        // Reset mid-flight, then a second member through the same hasher.
        feed(&mut hasher, &data[..cut], 256 << 10);
        hasher.reset();
        assert_eq!(hasher.spare.is_some(), wide, "reset keeps the second stage");
        feed(&mut hasher, &data, 64 << 10);
        assert_eq!(hasher.finalize_reset(), want, "after a reset mid-flight");
        // An allowance of two, a stream that shares the machine, never
        // turns, forced or not; nor does one worker.
        for workers in [1usize, 2] {
            let mut few_workers = Blake2sp::with_workers(workers);
            feed(&mut few_workers, &data, 256 << 10);
            assert!(!few_workers.feeder.gathers, "workers {workers}");
            assert_eq!(few_workers.finalize(), want, "workers {workers}");
        }
        // Dropped mid-flight: nothing dangles, and the helper is free for
        // the stream after it.
        let mut dropped = Blake2sp::with_workers(8);
        feed(&mut dropped, &data[..cut], 256 << 10);
        drop(dropped);
        let mut after = Blake2sp::with_workers(8);
        feed(&mut after, &data, 256 << 10);
        assert_eq!(after.finalize(), want, "the stream after a dropped one");
        // And with the rule not forced, a unit test's stream stays put.
        TEST_VERDICT.with(|k| k.set(None));
        let mut plain = Blake2sp::with_workers(8);
        feed(&mut plain, &data, 256 << 10);
        assert!(!plain.feeder.gathers);
        assert_eq!(plain.finalize(), want, "the rule off");
    }

    /// A member that ends lending on its feeder's verdict hands that
    /// verdict to the next member through the hasher (a solid chain's
    /// members share one hasher and one feeder), which gathers from its
    /// first feed into the stages the hasher already holds: every byte of
    /// it goes through the stage and none is hashed in place while the
    /// feeder waits. No pool is assumed beyond the hasher's own team or
    /// helper; memory, the 24 MiB input and two stages.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn a_member_after_a_lending_one_gathers_from_its_first_feed() {
        let data = filler(24 << 20);
        let cores = if cfg!(target_arch = "aarch64") { 8 } else { 2 };
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= cores);
        let member = &data[3 << 20..11 << 20];
        let feed = |hasher: &mut Blake2sp, bytes: &[u8]| {
            for chunk in bytes.chunks(1 << 20) {
                hasher.update(chunk);
            }
        };
        TEST_VERDICT.with(|k| k.set(Some(true)));
        let mut hasher = Blake2sp::with_workers(8);
        feed(&mut hasher, &data);
        assert_eq!(
            hasher.finalize_reset(),
            reference(&data),
            "the first member"
        );
        for round in 0..3 {
            // As the read path does: the last member's digest is taken,
            // then the hasher is started again for the next member.
            hasher.reset_for(8);
            let before = hasher.copied;
            LENDS.with(|n| n.set(0));
            feed(&mut hasher, member);
            let copied = hasher.copied - before;
            let lent = LENDS.with(std::cell::Cell::get);
            assert_eq!(hasher.finalize_reset(), reference(member), "round {round}");
            if wide {
                assert_eq!(
                    copied,
                    member.len(),
                    "round {round}: every byte is gathered"
                );
                assert!(lent >= 3, "round {round}: {lent} stages lent of 2 MiB each");
            } else {
                assert_eq!(lent, 0, "round {round}: nothing to lend to");
            }
        }
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// A handed verdict is checked once, at the member's first full
    /// stage: a member whose own feeder is not busy goes back to hashing
    /// in place for good and hands nothing on; a member too short to lend
    /// hands nothing on; and a member at one worker after a lending one
    /// lends nothing. Every digest is the reference's. No pool is assumed
    /// beyond the hasher's own team or helper; memory, the 24 MiB input
    /// and two stages.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn a_handed_verdict_is_checked_once_and_a_quiet_feeder_goes_back_in_place() {
        let data = filler(24 << 20);
        let cores = if cfg!(target_arch = "aarch64") { 8 } else { 2 };
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= cores);
        let member = &data[5 << 20..13 << 20];
        let feed = |hasher: &mut Blake2sp, bytes: &[u8]| {
            for chunk in bytes.chunks(1 << 20) {
                hasher.update(chunk);
            }
        };
        let lending = |hasher: &mut Blake2sp| {
            TEST_VERDICT.with(|k| k.set(Some(true)));
            feed(hasher, &data);
            assert_eq!(
                hasher.finalize_reset(),
                reference(&data),
                "a lending member"
            );
            assert_eq!(hasher.feeder.carried && hasher.feeder.unproved, wide);
        };
        let mut hasher = Blake2sp::with_workers(8);

        // The member after it has a feeder with nothing else to do.
        lending(&mut hasher);
        TEST_VERDICT.with(|k| k.set(Some(false)));
        let quiet = &data[5 << 20..17 << 20];
        hasher.reset_for(8);
        let before = hasher.copied;
        LENDS.with(|n| n.set(0));
        feed(&mut hasher, quiet);
        if wide {
            let feeder = hasher.feeder;
            assert!(!feeder.gathers && !feeder.unproved && !feeder.refused);
            assert!(feeder.carried, "it is not handed a verdict twice");
            assert_eq!(hasher.limit, BUFFER);
            // What was gathered before the question closed, and after it
            // only the rest of the feed it closed in.
            let copied = hasher.copied - before;
            assert!(
                copied <= PROVE_BY + SUSTAINED_STAGE + (1 << 20) + 8 * (GROUP + HOLD),
                "{copied} bytes gathered"
            );
            // The stages gathered meanwhile were lent; on aarch64 a full
            // stage is lent whatever the feeder (the staged arrangement).
            let lent = LENDS.with(std::cell::Cell::get);
            let most = if cfg!(target_arch = "aarch64") { 6 } else { 4 };
            assert!(lent <= most, "{lent} lends");
        }
        assert_eq!(
            hasher.finalize_reset(),
            reference(quiet),
            "the quiet member"
        );
        assert!(
            !hasher.feeder.gathers && !hasher.feeder.carried,
            "it hands nothing on"
        );
        assert_eq!((hasher.limit, hasher.lent), (BUFFER, 0));

        // A member too short to lend, after a lending one.
        lending(&mut hasher);
        let short = &data[..(1 << 20) + 123];
        feed(&mut hasher, short);
        assert_eq!(
            hasher.finalize_reset(),
            reference(short),
            "the short member"
        );
        assert!(
            !hasher.feeder.gathers && !hasher.feeder.carried,
            "it hands nothing on"
        );
        assert_eq!((hasher.limit, hasher.lent), (BUFFER, 0));

        // A member allowed one worker, after a lending one.
        lending(&mut hasher);
        hasher.reset_for(1);
        LENDS.with(|n| n.set(0));
        feed(&mut hasher, member);
        assert_eq!(
            LENDS.with(std::cell::Cell::get),
            0,
            "one worker lends nothing"
        );
        assert_eq!(hasher.limit, BUFFER);
        assert!(
            !hasher.feeder.carried,
            "it drops the verdict at its first byte"
        );
        assert!(
            hasher.copied <= BUFFER + 16 * (GROUP + HOLD),
            "and gathers no stage"
        );
        assert_eq!(
            hasher.finalize_reset(),
            reference(member),
            "the one worker member"
        );
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// A NAMED WIDTH IS A PROMISE: at a width of one the lend forms add
    /// no thread and no turn, whatever the member's allowance (the read
    /// path's allowance at a stated width of one is 7 under the tool's
    /// default policy). With the feeder rule forced, such a
    /// member never turns to gathering, takes no helper thread, lends
    /// nothing, and neither takes a verdict from the member before it
    /// nor hands one on; and the gate is the member's own, so a member
    /// at a wider width through the same hasher lends as ever. No pool
    /// is assumed beyond the hasher's own team or helper; memory, the 24
    /// MiB input and two stages.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn a_member_read_at_a_width_of_one_starts_no_helper_and_lends_nothing() {
        let data = filler(24 << 20);
        let cores = if cfg!(target_arch = "aarch64") { 8 } else { 2 };
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= cores);
        let member = &data[3 << 20..11 << 20];
        let feed = |hasher: &mut Blake2sp, bytes: &[u8]| {
            for chunk in bytes.chunks(1 << 20) {
                hasher.update(chunk);
            }
        };
        let clear = || {
            LENDS.with(|n| n.set(0));
            #[cfg(target_arch = "x86_64")]
            beside::DESKS_TAKEN.with(|n| n.set(0));
        };
        // What a member at a width of one must show once it is fed.
        let stayed = |hasher: &Blake2sp, what: &str| {
            assert!(!hasher.feeder.gathers, "{what}: it never turns");
            assert_eq!(
                LENDS.with(std::cell::Cell::get),
                0,
                "{what}: it lends nothing"
            );
            #[cfg(target_arch = "x86_64")]
            assert_eq!(
                beside::DESKS_TAKEN.with(std::cell::Cell::get),
                0,
                "{what}: it takes no helper thread"
            );
            assert!(
                hasher.copied <= BUFFER + 32 * (GROUP + HOLD),
                "{what}: it gathers no stage, {} copied",
                hasher.copied
            );
        };
        TEST_VERDICT.with(|k| k.set(Some(true)));
        for workers in [7usize, 8, 32] {
            let mut hasher = Blake2sp::with_workers(workers);
            // Member after member at a width of one.
            for (round, bytes) in [&data[..], member, member].into_iter().enumerate() {
                let what = format!("workers {workers} round {round}");
                hasher.arm(Armed { workers, width: 1 });
                clear();
                feed(&mut hasher, bytes);
                stayed(&hasher, &what);
                assert_eq!(hasher.finalize_reset(), reference(bytes), "{what}");
                assert!(
                    !hasher.feeder.gathers && !hasher.feeder.carried,
                    "{what}: it hands nothing on"
                );
            }
            // A wider member through the same hasher lends as ever, and
            // hands its verdict on.
            hasher.arm(Armed { workers, width: 8 });
            clear();
            feed(&mut hasher, &data);
            assert_eq!(
                LENDS.with(std::cell::Cell::get) > 0,
                wide,
                "workers {workers}"
            );
            assert_eq!(hasher.finalize_reset(), reference(&data), "the wide member");
            assert_eq!(hasher.feeder.unproved, wide, "workers {workers}");
            // The member after it, at a width of one, drops that verdict
            // at its first byte.
            let what = format!("workers {workers} after a lending member");
            hasher.arm(Armed { workers, width: 1 });
            clear();
            feed(&mut hasher, member);
            stayed(&hasher, &what);
            assert!(!hasher.feeder.carried && !hasher.feeder.unproved, "{what}");
            assert_eq!(hasher.limit, BUFFER, "{what}");
            assert_eq!(hasher.finalize_reset(), reference(member), "{what}");
            assert!(!hasher.feeder.gathers && !hasher.feeder.carried, "{what}");
        }
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// Feeds this thread's hashers have relayed since the count was cleared.
    #[cfg(target_arch = "aarch64")]
    fn relayed() -> usize {
        RELAYED.with(std::cell::Cell::get)
    }

    /// Whether this box and build give a team of more than two to relay to.
    #[cfg(target_arch = "aarch64")]
    fn relays_here() -> bool {
        cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 8)
    }

    /// A STORED MEMBER'S FEEDS ARE RELAYED, AND THE DIGEST IS THE ONE IN
    /// PLACE. Armed stored at widths 4, 6 and 8 (the team of four, four and
    /// eight), fed in runs that clear the in-place threshold, cut where a
    /// feed is shorter than a stage, longer than one, and not a whole group:
    /// every digest is the RFC transcription's and the independent crate's,
    /// and on a box with the cores for it feeds were relayed. No pool is
    /// assumed beyond the hasher's own team and relay; memory, the 24 MiB
    /// input and the relay's stages (6 MiB).
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_stored_members_feeds_are_relayed_and_the_digest_holds() {
        let data = filler((24 << 20) + 777);
        let want = reference(&data);
        assert_eq!(want, *blake2s_simd::blake2sp::blake2sp(&data).as_array());
        for width in [4usize, 6, 8] {
            let mut hasher = Blake2sp::with_workers(width);
            for chunk in [1 << 20, 2 << 20, (4 << 20) + 513, (5 << 20) - 1, 9 << 20] {
                let what = format!("width {width} chunk {chunk}");
                hasher.arm_member(
                    Armed {
                        workers: width,
                        width,
                    },
                    true,
                );
                RELAYED.with(|n| n.set(0));
                for piece in data.chunks(chunk) {
                    hasher.update(piece);
                }
                assert_eq!(hasher.finalize_reset(), want, "{what}");
                assert_eq!(relayed() > 0, relays_here(), "{what}: relayed");
            }
            assert!(
                hasher.relay_stages.len() <= RELAY_STAGES,
                "width {width}: at most {RELAY_STAGES} stages"
            );
            assert_eq!(
                hasher.relay_charge.bytes(),
                (hasher.relay_stages.len() * RELAY_STAGE) as u64,
                "width {width}: every stage charged"
            );
        }
    }

    /// NOTHING ELSE IS RELAYED: a stored member at a width of one (the
    /// read path's allowance of 7 beside it), and a member that is not
    /// stored, hash as before, relay nothing and take no stage. No pool is
    /// assumed beyond the hasher's own team; memory, the 24 MiB input.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_width_of_one_or_a_decoded_member_relays_nothing() {
        let data = filler(24 << 20);
        let want = reference(&data);
        for (armed, stored) in [
            (
                Armed {
                    workers: 7,
                    width: 1,
                },
                true,
            ),
            (
                Armed {
                    workers: 8,
                    width: 8,
                },
                false,
            ),
        ] {
            let mut hasher = Blake2sp::with_workers(armed.workers);
            hasher.arm_member(armed, stored);
            RELAYED.with(|n| n.set(0));
            for piece in data.chunks(2 << 20) {
                hasher.update(piece);
            }
            assert_eq!(hasher.finalize_reset(), want, "{armed:?} stored {stored}");
            assert_eq!(relayed(), 0, "{armed:?} stored {stored}: relayed nothing");
            assert!(hasher.relay_stages.is_empty(), "{armed:?}: no stage");
        }
    }

    /// A CLONE TAKEN WITH A RUN OUT is the stream so far: it waits for the
    /// relay, copies the leaves, and both go on to the reference digest. No
    /// pool is assumed beyond the hasher's own team and relay; memory, two
    /// 16 MiB inputs and the stages.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_clone_of_a_relaying_stream_is_the_stream_so_far() {
        let data = filler(32 << 20);
        let mut hasher = Blake2sp::with_workers(8);
        hasher.arm_member(
            Armed {
                workers: 8,
                width: 8,
            },
            true,
        );
        for piece in data[..16 << 20].chunks(2 << 20) {
            hasher.update(piece);
        }
        let mut twin = hasher.clone();
        for piece in data[16 << 20..].chunks(3 << 20) {
            hasher.update(piece);
            twin.update(piece);
        }
        let want = reference(&data);
        assert_eq!(twin.finalize(), want, "the clone");
        assert_eq!(hasher.finalize(), want, "the original");
    }

    /// A HASHER DROPPED WITH A RUN OUT leaves nothing behind: its team
    /// and relay go mid-member (a read that stops short of a member's end),
    /// and the relay is parked. The next stream, which leases that parked
    /// relay, begins its own run from its own leaves: every digest after is
    /// the reference's. No pool is assumed beyond the hashers' own teams and
    /// relays; memory, the 16 MiB input and one hasher's stages at a time.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_hasher_dropped_mid_run_leaves_the_next_digest_whole() {
        let data = filler(16 << 20);
        let want = reference(&data);
        for round in 0..4 {
            let mut dropped = Blake2sp::with_workers(8);
            dropped.arm_member(
                Armed {
                    workers: 8,
                    width: 8,
                },
                true,
            );
            for piece in data[..10 << 20].chunks(2 << 20) {
                dropped.update(piece);
            }
            drop(dropped);
            let mut hasher = Blake2sp::with_workers(8);
            hasher.arm_member(
                Armed {
                    workers: 8,
                    width: 8,
                },
                true,
            );
            for piece in data.chunks(2 << 20) {
                hasher.update(piece);
            }
            assert_eq!(hasher.finalize_reset(), want, "round {round}");
        }
    }

    /// AT MOST `RELAYS_MOST` HASHERS HOLD RELAY STAGES: a third stored
    /// stream alongside two that relay hashes in place, takes no stage and
    /// gives the reference digest, and a place given back is taken again.
    /// No pool is assumed beyond the hashers' own teams and relays; memory,
    /// the 8 MiB input and two hashers' stages.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn at_most_two_hashers_hold_relay_stages() {
        if !relays_here() {
            return;
        }
        let data = filler(8 << 20);
        let want = reference(&data);
        let mut held: Vec<Blake2sp> = Vec::new();
        for n in 0..3 {
            let mut hasher = Blake2sp::with_workers(8);
            hasher.arm_member(
                Armed {
                    workers: 8,
                    width: 8,
                },
                true,
            );
            for piece in data.chunks(2 << 20) {
                hasher.update(piece);
            }
            assert_eq!(hasher.finalize_reset(), want, "hasher {n}");
            assert_eq!(hasher.relay_place, n < RELAYS_MOST, "hasher {n}: a place");
            assert_eq!(
                hasher.relay_stages.is_empty(),
                n >= RELAYS_MOST,
                "hasher {n}"
            );
            held.push(hasher);
        }
        held.remove(0);
        let mut again = Blake2sp::with_workers(8);
        again.arm_member(
            Armed {
                workers: 8,
                width: 8,
            },
            true,
        );
        for piece in data.chunks(2 << 20) {
            again.update(piece);
        }
        assert_eq!(again.finalize_reset(), want, "after a place is given back");
        assert!(again.relay_place, "the place given back is taken");
    }

    /// A NAMED WIDTH OF ONE IS ONE THREAD AT WORK. Armed at a width of one
    /// with the allowance the read path gives there (7 under the tool's
    /// default policy), a member's hash is built at an allowance of one
    /// and takes no team at all, so the lanes run on the calling thread:
    /// counted on an M1 Ultra, 15 Oct 2026, `x -mt1` of one stored 4 GiB
    /// member ran FOUR threads (the walk and three leaf threads, 3.00 CPU
    /// over wall) where x86-64 ran one. The allowance a stream hashes at
    /// (`chosen`) is the team it builds and widens to; it must stay one,
    /// one-shot and chunked, lent nothing; and the same hasher armed at a
    /// wider width afterwards builds its team as ever. No pool is assumed
    /// beyond the hasher's own team; memory, the 24 MiB input and a stage.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn a_member_read_at_a_width_of_one_hashes_on_the_calling_thread() {
        let data = filler(24 << 20);
        // At the wider width `chosen` is the caller's allowance (above one
        // for every `workers` here), whatever the machine: it is not the
        // core count. Tying it to eight hardware threads failed on a four
        // thread hosted runner (FROM-STUDIO 531 A).
        let wide = cfg!(feature = "parallel");
        for workers in [7usize, 8, 32] {
            let mut hasher = Blake2sp::with_workers(workers);
            for (what, chunk) in [("one shot", data.len()), ("chunked", 1 << 20)] {
                let what = format!("workers {workers} {what}");
                hasher.arm(Armed { workers, width: 1 });
                LENDS.with(|n| n.set(0));
                for piece in data.chunks(chunk) {
                    hasher.update(piece);
                }
                assert_eq!(hasher.chosen, 1, "{what}: it hashes at an allowance of one");
                assert_eq!(
                    LENDS.with(std::cell::Cell::get),
                    0,
                    "{what}: it lends nothing"
                );
                assert_eq!(hasher.finalize_reset(), reference(&data), "{what}");
            }
            // The same hasher at a wider width builds its team as ever.
            hasher.arm(Armed { workers, width: 8 });
            hasher.update(&data);
            assert_eq!(hasher.chosen > 1, wide, "workers {workers} width 8");
            assert_eq!(
                hasher.finalize_reset(),
                reference(&data),
                "workers {workers} width 8"
            );
        }
    }

    /// A STORED MEMBER NEVER TURNS. A stored member has no decode for its
    /// hash to run beside, so a lend there buys nothing by the form's own
    /// reason and costs a copy of every byte (counted on a Zen 4, 13 Oct
    /// 2026: of sixteen stored members of 256 MiB read at once ONE turned
    /// and lent a whole member, and the row read 0.92 of main; with no
    /// stored member turning it read 1.00). With the feeder rule forced,
    /// a member the read path arms as stored never turns to gathering,
    /// takes no helper thread, lends nothing, and neither takes a verdict
    /// from the member before it nor hands one on, at any width; and the
    /// gate is the member's own, so a COMPRESSED member through the same
    /// hasher, before it and after it, turns and lends as ever. No pool
    /// is assumed beyond the hasher's own team or helper; memory, the 24
    /// MiB input and two stages.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn a_stored_member_never_turns_and_a_compressed_one_still_may() {
        let data = filler(24 << 20);
        let cores = if cfg!(target_arch = "aarch64") { 8 } else { 2 };
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= cores);
        let member = &data[3 << 20..11 << 20];
        let feed = |hasher: &mut Blake2sp, bytes: &[u8]| {
            for chunk in bytes.chunks(1 << 20) {
                hasher.update(chunk);
            }
        };
        let clear = || {
            LENDS.with(|n| n.set(0));
            #[cfg(target_arch = "x86_64")]
            beside::DESKS_TAKEN.with(|n| n.set(0));
        };
        // What a stored member must show once it is fed.
        let stayed = |hasher: &Blake2sp, what: &str| {
            assert!(!hasher.feeder.gathers, "{what}: it never turns");
            assert_eq!(hasher.feeder.turns, 0, "{what}: no turn is counted");
            assert_eq!(
                LENDS.with(std::cell::Cell::get),
                0,
                "{what}: it lends nothing"
            );
            #[cfg(target_arch = "x86_64")]
            assert_eq!(
                beside::DESKS_TAKEN.with(std::cell::Cell::get),
                0,
                "{what}: it takes no helper thread"
            );
            assert!(
                hasher.copied <= BUFFER + 32 * (GROUP + HOLD),
                "{what}: it gathers no stage, {} copied",
                hasher.copied
            );
        };
        TEST_VERDICT.with(|k| k.set(Some(true)));
        for (workers, width) in [(8usize, 8usize), (16, 16), (32, 8)] {
            let armed = Armed { workers, width };
            let mut hasher = Blake2sp::with_workers(workers);
            // Stored member after stored member, at a width above one.
            for (round, bytes) in [&data[..], member, member].into_iter().enumerate() {
                let what = format!("workers {workers} width {width} stored round {round}");
                hasher.arm_member(armed, true);
                clear();
                feed(&mut hasher, bytes);
                stayed(&hasher, &what);
                assert_eq!(hasher.finalize_reset(), reference(bytes), "{what}");
                assert!(
                    !hasher.feeder.gathers && !hasher.feeder.carried,
                    "{what}: it hands nothing on"
                );
            }
            // A compressed member through the same hasher turns and
            // lends as ever, and hands its verdict on.
            let what = format!("workers {workers} width {width} compressed");
            hasher.arm_member(armed, false);
            clear();
            feed(&mut hasher, &data);
            assert_eq!(LENDS.with(std::cell::Cell::get) > 0, wide, "{what}");
            assert_eq!(hasher.feeder.gathers, wide, "{what}: it turns");
            assert_eq!(hasher.finalize_reset(), reference(&data), "{what}");
            assert_eq!(hasher.feeder.unproved, wide, "{what}");
            // The stored member after it drops that verdict at its first
            // byte.
            let what = format!("workers {workers} width {width} stored after a lending member");
            hasher.arm_member(armed, true);
            clear();
            feed(&mut hasher, member);
            stayed(&hasher, &what);
            assert!(!hasher.feeder.carried && !hasher.feeder.unproved, "{what}");
            assert_eq!(hasher.limit, BUFFER, "{what}");
            assert_eq!(hasher.finalize_reset(), reference(member), "{what}");
            assert!(!hasher.feeder.gathers && !hasher.feeder.carried, "{what}");
            // And the compressed member after THAT is not held by it.
            let what = format!("workers {workers} width {width} compressed after a stored member");
            hasher.arm(armed);
            clear();
            feed(&mut hasher, &data);
            assert_eq!(LENDS.with(std::cell::Cell::get) > 0, wide, "{what}");
            assert_eq!(hasher.finalize_reset(), reference(&data), "{what}");
        }
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// AT MOST TWO TURNS TO LENDING A MEMBER. A carried member turns once
    /// on the verdict handed to it; if that verdict fails its check it
    /// goes back in place and may turn once more by its own timed rule,
    /// and then it keeps lending. It cannot turn a third time whatever
    /// its feeds do: put back in place by hand, a state the hasher
    /// itself reaches only through a refused stage, with the rule forced
    /// to say lend at every feed, it stays in place. No pool is assumed
    /// beyond the hasher's own team or helper; memory, the 48 MiB input
    /// and two stages.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn a_member_turns_to_lending_twice_at_the_most() {
        let data = filler(48 << 20);
        let cores = if cfg!(target_arch = "aarch64") { 8 } else { 2 };
        if !(cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= cores))
        {
            return;
        }
        let feed = |hasher: &mut Blake2sp, bytes: &[u8]| {
            for chunk in bytes.chunks(1 << 20) {
                hasher.update(chunk);
            }
        };
        // A member that turns by its own rule has turned once.
        TEST_VERDICT.with(|k| k.set(Some(true)));
        let mut hasher = Blake2sp::with_workers(8);
        feed(&mut hasher, &data[..24 << 20]);
        assert!(hasher.feeder.gathers);
        assert_eq!(hasher.feeder.turns, 1, "an ordinary member");
        assert_eq!(hasher.finalize_reset(), reference(&data[..24 << 20]));
        // The member after it is handed the verdict: its first turn.
        hasher.reset_for(8);
        assert!(hasher.feeder.carried && hasher.feeder.gathers);
        assert_eq!(hasher.feeder.turns, 1, "a handed verdict is a turn");
        // The handed verdict fails its check: back in place, one turn
        // spent.
        TEST_VERDICT.with(|k| k.set(Some(false)));
        let mut fed = 12 << 20;
        feed(&mut hasher, &data[..fed]);
        assert!(!hasher.feeder.gathers && !hasher.feeder.refused);
        assert_eq!(hasher.feeder.turns, 1, "back in place");
        // Its own timed rule turns it once more, and it keeps lending.
        TEST_VERDICT.with(|k| k.set(Some(true)));
        feed(&mut hasher, &data[fed..fed + (8 << 20)]);
        fed += 8 << 20;
        assert!(hasher.feeder.gathers);
        assert_eq!(hasher.feeder.turns, 2, "the second turn");
        feed(&mut hasher, &data[fed..fed + (6 << 20)]);
        fed += 6 << 20;
        assert!(hasher.feeder.gathers, "it keeps lending");
        assert_eq!(hasher.feeder.turns, 2);
        // Put back in place by hand, with the rule still saying lend at
        // every feed: there is no third turn.
        hasher.feeder.gathers = false;
        for chunk in data[fed..fed + (12 << 20)].chunks(1 << 20) {
            hasher.update(chunk);
            assert!(!hasher.feeder.gathers, "a third turn");
            assert_eq!(hasher.feeder.turns, 2, "a third turn");
        }
        fed += 12 << 20;
        assert_eq!(hasher.finalize_reset(), reference(&data[..fed]));
        // A member that ended in place hands nothing on, and the member
        // after it begins with no turn spent.
        hasher.reset_for(8);
        assert!(!hasher.feeder.gathers && !hasher.feeder.carried);
        assert_eq!(hasher.feeder.turns, 0);
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// THE BOUND ON HELPERS, x86-64: however many streams lend at once, a
    /// thread's helpers are never more than `HELPERS_MOST`, flying or
    /// parked; a stream that finds them all out is refused and hashes in
    /// place to its end with the digest a hasher that never lent gives;
    /// and once every hasher is dropped the helpers are parked, none
    /// lost, none over the ceiling. Under test a thread has its own
    /// helpers, as it has its own census, so this fills no other test's
    /// ceiling. No pool is assumed; memory, the 24 MiB input and two
    /// stages a stream, eight streams.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn helper_threads_are_bounded_and_a_stream_over_the_bound_hashes_in_place() {
        use beside::{helpers, HELPERS_MOST};
        let data = filler(24 << 20);
        let want = reference(&data);
        if !(cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 2))
        {
            return;
        }
        assert_eq!((helpers().alive(), helpers().parked()), (0, 0));
        TEST_VERDICT.with(|k| k.set(Some(true)));
        // One stream turns and lends; its helper is out on a flight.
        let mut first = Blake2sp::with_workers(8);
        let cut = 9 << 20;
        for chunk in data[..cut].chunks(1 << 20) {
            first.update(chunk);
        }
        assert!(first.feeder.gathers && first.lent > 0);
        assert_eq!(helpers().alive(), 1);
        // Clones of it are lending streams from their first feed. Each is
        // fed until it has a flight out, and is then left holding it.
        let streams = HELPERS_MOST + 3;
        let mut clones: Vec<Blake2sp> = (0..streams).map(|_| first.clone()).collect();
        let mut at = vec![cut; streams];
        for (i, clone) in clones.iter_mut().enumerate() {
            let before = LENDS.with(std::cell::Cell::get);
            while LENDS.with(std::cell::Cell::get) == before && !clone.feeder.refused {
                clone.update(&data[at[i]..at[i] + (1 << 20)]);
                at[i] += 1 << 20;
                assert!(helpers().alive() <= HELPERS_MOST, "stream {i}");
            }
            // `first` holds one helper, so the ceiling is reached one
            // clone early: the rest are refused and lend nothing.
            let refused = i + 1 >= HELPERS_MOST;
            assert_eq!(clone.feeder.refused, refused, "stream {i}");
            assert_eq!(clone.feeder.gathers, !refused, "stream {i}");
        }
        assert_eq!(helpers().alive(), HELPERS_MOST);
        assert_eq!(helpers().parked(), 0, "every helper is out on a flight");
        // A stream that begins now is refused at its first stage too.
        let mut late = Blake2sp::with_workers(8);
        for chunk in data.chunks(1 << 20) {
            late.update(chunk);
        }
        assert!(late.feeder.refused || !late.feeder.gathers);
        assert_eq!(late.finalize(), want, "the late stream");
        assert_eq!(helpers().alive(), HELPERS_MOST);
        // Every stream ends with the one digest, refused or not.
        for (i, mut clone) in clones.into_iter().enumerate() {
            for chunk in data[at[i]..].chunks(700 << 10) {
                clone.update(chunk);
            }
            assert_eq!(clone.finalize(), want, "stream {i}");
            assert!(helpers().alive() <= HELPERS_MOST);
        }
        for chunk in data[cut..].chunks(1 << 20) {
            first.update(chunk);
        }
        assert_eq!(first.finalize(), want, "the first stream");
        // Nothing is left out, and nothing over the ceiling is left.
        assert_eq!(helpers().alive(), HELPERS_MOST);
        assert_eq!(helpers().parked(), HELPERS_MOST);
        // The helpers that are parked are the ones the next streams use.
        let mut after = Blake2sp::with_workers(8);
        for chunk in data.chunks(1 << 20) {
            after.update(chunk);
        }
        assert!(after.feeder.gathers, "a helper is to be had again");
        assert_eq!(after.finalize(), want, "the stream after");
        assert_eq!(
            (helpers().alive(), helpers().parked()),
            (HELPERS_MOST, HELPERS_MOST)
        );
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// THE MOST A PROCESS HOLDS FOR LENDING stays under the process
    /// headroom the memory policy pins: the hashers that may hold the
    /// longer pair at once, times what one holds over the in-place
    /// arrangement. `MemoryPolicy::PROCESS_HEADROOM` is 32 MiB and its own
    /// comment (`memory.rs`) says what was counted under it, 22.6 MiB at
    /// the most, so it has 9 MiB to spare; the bound is held under that
    /// too. And the ceiling is real: of four hashers that each lend a
    /// long member and are then kept, as a pool keeps its workers'
    /// hashers, two hold the longer pair and two lend the stages they
    /// have; every digest is the reference's; the allocator's peak over
    /// all four is the bound and four in-place stages over; and a place
    /// given back is taken by the next hasher that would grow. No pool is
    /// assumed beyond the hasher's own team or helper; memory, the 24 MiB
    /// input and that bound.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn the_longer_pairs_of_a_process_stay_under_the_headroom() {
        use crate::rar3_filters::tests::counting;

        let most = (PAIRS_MOST * LENDING_OVER) as u64;
        assert!(most < crate::MemoryPolicy::PROCESS_HEADROOM);
        // What `memory.rs` counted under the headroom, from its comment
        // on `PROCESS_HEADROOM`: 22.6 MiB at the most.
        let counted = 226 * (1u64 << 20) / 10;
        assert!(most <= crate::MemoryPolicy::PROCESS_HEADROOM - counted);

        let data = filler(24 << 20);
        let want = reference(&data);
        let cores = if cfg!(target_arch = "aarch64") { 8 } else { 2 };
        if !(cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= cores))
        {
            return;
        }
        TEST_VERDICT.with(|k| k.set(Some(true)));
        let lend = |hasher: &mut Blake2sp| {
            for chunk in data.chunks(1 << 20) {
                hasher.update(chunk);
            }
            assert!(hasher.feeder.gathers && hasher.lent > 0, "it lends");
            assert_eq!(hasher.finalize_reset(), want);
        };
        // Warm the team or the helper: what they allocate once is theirs.
        {
            let mut warm = Blake2sp::with_workers(8);
            lend(&mut warm);
        }
        assert_eq!(PAIRS_HERE.with(std::cell::Cell::get), 0);
        counting::reset_peak();
        let mut kept: Vec<Blake2sp> = Vec::with_capacity(PAIRS_MOST + 2);
        for i in 0..PAIRS_MOST + 2 {
            let mut hasher = Blake2sp::with_workers(8);
            lend(&mut hasher);
            assert_eq!(hasher.paired, i < PAIRS_MOST, "hasher {i}");
            let long = hasher.stage.len() > BUFFER
                || hasher.spare.as_ref().is_some_and(|s| s.len() > BUFFER);
            assert_eq!(long, i < PAIRS_MOST, "hasher {i}");
            kept.push(hasher);
            assert!(PAIRS_HERE.with(std::cell::Cell::get) <= PAIRS_MOST);
        }
        let peak = counting::peak_bytes();
        let allowed = most + ((PAIRS_MOST + 2) * 2 * BUFFER + (64 << 10)) as u64;
        assert!(
            peak <= allowed,
            "peak {peak} bytes over four kept hashers, {allowed} allowed"
        );
        // A hasher that lets its pair go leaves room for the next: one is
        // dropped, and one starts a member that drops what it was handed.
        drop(kept.remove(0));
        assert_eq!(PAIRS_HERE.with(std::cell::Cell::get), PAIRS_MOST - 1);
        kept[0].arm(Armed {
            workers: 8,
            width: 1,
        });
        kept[0].update(&data[..4096]);
        assert!(!kept[0].paired && kept[0].stage.len() == BUFFER && kept[0].spare.is_none());
        assert_eq!(kept[0].finalize_reset(), reference(&data[..4096]));
        assert_eq!(PAIRS_HERE.with(std::cell::Cell::get), 0);
        let last = kept.len() - 1;
        kept[last].reset_for(8);
        lend(&mut kept[last]);
        assert!(kept[last].paired, "the place is taken again");
        drop(kept);
        assert_eq!(PAIRS_HERE.with(std::cell::Cell::get), 0);
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// WHAT A LENDING STREAM HOLDS, on both lending targets: two stages
    /// of `SUSTAINED_STAGE` at the most and never a third
    /// (`LENDING_STAGES`, 4,196,352 bytes), whatever the length of the
    /// stream, across a chain of members through one hasher, and across a
    /// member that goes back to hashing in place. Counted from the
    /// allocator. No pool is assumed beyond the hasher's own team or
    /// helper; memory, the 48 MiB input and that figure.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn a_lending_stream_holds_two_stages_and_never_a_third() {
        use crate::rar3_filters::tests::counting;

        let data = filler(48 << 20);
        let want = reference(&data);
        let cores = if cfg!(target_arch = "aarch64") { 8 } else { 2 };
        let wide = cfg!(feature = "parallel")
            && std::thread::available_parallelism().is_ok_and(|n| n.get() >= cores);
        TEST_VERDICT.with(|k| k.set(Some(true)));
        // Warm the team or the helper: what they allocate once is theirs.
        {
            let mut warm = Blake2sp::with_workers(8);
            for chunk in data[..16 << 20].chunks(1 << 20) {
                warm.update(chunk);
            }
            let _ = warm.finalize();
        }
        // The reference digests first: they allocate, and are not the
        // hasher's.
        let members: Vec<&[u8]> = (0..4usize)
            .map(|round| &data[round << 20..(round + 12) << 20])
            .collect();
        let wants: Vec<[u8; 32]> = members.iter().map(|m| reference(m)).collect();
        counting::reset_peak();
        let mut hasher = Blake2sp::with_workers(8);
        let held = |hasher: &Blake2sp| {
            let stages = hasher.stage.len() + hasher.spare.as_ref().map_or(0, |s| s.len());
            assert!(
                stages <= LENDING_STAGES,
                "{stages} bytes of stage in the hasher's hands"
            );
        };
        for chunk in data.chunks(1 << 20) {
            hasher.update(chunk);
            held(&hasher);
        }
        assert_eq!(hasher.feeder.gathers, wide);
        assert_eq!(hasher.finalize_reset(), want, "the long member");
        // A chain of members through the same hasher, the last of them
        // one that goes back to hashing in place.
        for (round, member) in members.iter().enumerate() {
            hasher.reset_for(8);
            if round == 3 {
                TEST_VERDICT.with(|k| k.set(Some(false)));
            }
            for chunk in member.chunks(1 << 20) {
                hasher.update(chunk);
                held(&hasher);
            }
            assert_eq!(hasher.finalize_reset(), wants[round], "round {round}");
        }
        let peak = counting::peak_bytes();
        let most = if wide { LENDING_STAGES } else { BUFFER };
        assert!(
            peak <= (most + (64 << 10)) as u64,
            "peak {peak} bytes over a lending hasher's life, {most} allowed"
        );
        drop(hasher);
        TEST_VERDICT.with(|k| k.set(None));
    }

    /// The knob's words: off, a count of pool thresholds, and the shipped
    /// batch for anything else or nothing.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_sustained_knob_reads_its_words_and_ships_on() {
        assert_eq!(sustained_of(None), Some(SUSTAINED_STAGE));
        assert_eq!(sustained_of(Some("0")), None);
        assert_eq!(sustained_of(Some(" OFF ")), None);
        assert_eq!(sustained_of(Some("2")), Some(2 * POOL_MIN_BATCH + HOLD));
        assert_eq!(sustained_of(Some("4")), Some(SUSTAINED_STAGE));
        assert_eq!(sustained_of(Some("16")), Some(16 * POOL_MIN_BATCH + HOLD));
        assert_eq!(sustained_of(Some("1")), Some(SUSTAINED_STAGE));
        assert_eq!(sustained_of(Some("65")), Some(SUSTAINED_STAGE));
        assert_eq!(sustained_of(Some("on")), Some(SUSTAINED_STAGE));
    }

    /// A hasher started again for a member with another allowance holds
    /// that allowance, and the digest is a fresh hasher's either way.
    #[test]
    fn a_hasher_started_again_takes_the_new_allowance() {
        let data = filler(3 * BUFFER + 77);
        let want = reference(&data);
        let mut hasher = Blake2sp::with_workers(7);
        hasher.update(&data[..BUFFER]);
        forget_allowance();
        hasher.reset_for(1);
        assert_eq!(last_allowance(), 1);
        assert_eq!((hasher.workers, hasher.chosen), (1, 1));
        hasher.update(&data);
        assert_eq!(hasher.finalize_reset(), want);
        hasher.reset_for(8);
        let allowed = if cfg!(feature = "parallel") { 8 } else { 1 };
        assert_eq!((hasher.workers, hasher.chosen), (allowed, allowed));
        hasher.update(&data);
        assert_eq!(hasher.finalize_reset(), want);
    }

    /// A hasher with a stage in flight can be cloned, reset, finished or
    /// dropped at any point, and each gives what a hasher that never lent
    /// gives; reset keeps the second stage, so a hasher reused member after
    /// member takes it once.
    #[test]
    fn a_hasher_with_a_stage_in_flight_clones_resets_and_drops() {
        let data = filler(BUFFER * 5 + 777);
        let want = blake2sp(&data);
        let cut = BUFFER * 2 + 4096;
        let mut hasher = Blake2sp::with_workers(8);
        for chunk in data[..cut].chunks(4096) {
            hasher.update(chunk);
        }
        // A clone mid-flight, finished on its own.
        let mut clone = hasher.clone();
        clone.update(&data[cut..]);
        assert_eq!(clone.finalize(), want, "the clone");
        // The original, carried on after its clone was taken.
        for chunk in data[cut..].chunks(4096) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize_reset(), want, "the original");
        // Reset mid-flight, then a second member through the same hasher.
        for chunk in data[..cut].chunks(4096) {
            hasher.update(chunk);
        }
        hasher.reset();
        #[cfg(target_arch = "aarch64")]
        if LENDS.with(std::cell::Cell::get) > 0 {
            assert!(hasher.spare.is_some(), "reset keeps the second stage");
        }
        for chunk in data.chunks(64 << 10) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize_reset(), want, "after a reset mid-flight");
        // Dropped mid-flight: nothing waits for it and nothing dangles.
        let mut dropped = Blake2sp::with_workers(8);
        for chunk in data[..cut].chunks(4096) {
            dropped.update(chunk);
        }
        drop(dropped);
    }

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
