//! The pool: the workers, what is in flight, and the order answers settle in.

use super::*;

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// A member a worker is decoding, waiting for its `close`.
///
/// The member's NAME is not here: the worker holds it, uses it to name the
/// errors it raises and hands it back with its answer, so the walk copies
/// it once and the pool keeps no second copy of it.
pub(super) struct Sent<W> {
    pub(super) file: FileHdr,
    pub(super) data: std::ops::Range<u64>,
    pub(super) worker: usize,
    /// The worker's answer, when it arrived before this member's turn to
    /// close and the worker was freed for another member. Always `None`
    /// at an outputs factor of 1, where a worker is held until its member
    /// closes ([`OUTPUTS_OVER_BREADTH_ENV`]).
    pub(super) answer: Option<Done<W>>,
    /// A member below the offload floor, which counts against the member
    /// team's width ([`SMALL_TEAM_ENV`]).
    pub(super) below: bool,
    /// Whether the member holds the caller's writer (`x`), which is what
    /// the outputs bound counts under [`QUEUE_OWN_ENV`].
    pub(super) writes: bool,
}

/// A member the WALK handled itself, waiting for its turn to close
/// ([`QUEUE_OWN_ENV`]): everything `Pool::close` or `Pool::skipped` was
/// given, kept until every member ahead of it has closed.
pub(super) struct Own<W> {
    /// The member as the walk described it, less its two borrowed fields.
    pub(super) info: MemberInfo<'static>,
    pub(super) name: Vec<u8>,
    /// A redirection's target, where the walk gave one.
    pub(super) target: Option<Vec<u8>>,
    /// The caller's writer, back for its `close`.
    pub(super) out: Option<W>,
    pub(super) outcome: MemberOutcome,
    pub(super) err: Option<Error>,
    /// The sink skipped it: counted at its turn, with no `close`.
    pub(super) skipped: bool,
}

/// One member waiting for its `close`, in archive order.
///
/// Both kinds are boxed: a queue that is thousands of entries long under
/// [`QUEUE_OWN_ENV`] is then sixteen bytes an entry, and a dispatched
/// member's header and parked answer (about half a kilobyte) are not the
/// size of every entry the walk queues behind it.
pub(super) enum Flight<W> {
    /// A worker is decoding it, or has answered.
    Sent(Box<Sent<W>>),
    /// The walk handled it; only its turn is waited for.
    Own(Box<Own<W>>),
}

impl<W> Flight<W> {
    /// The member, where a worker is still decoding it.
    pub(super) fn decoding(&self) -> Option<&Sent<W>> {
        match self {
            Flight::Sent(sent) if sent.answer.is_none() => Some(sent.as_ref()),
            _ => None,
        }
    }

    /// Park a worker's answer beside its member.
    pub(super) fn answer(&mut self, done: Done<W>) {
        if let Flight::Sent(sent) = self {
            sent.answer = Some(done);
        }
    }

    /// Whether it holds the caller's writer.
    pub(super) fn writes(&self) -> bool {
        match self {
            Flight::Sent(sent) => sent.writes,
            Flight::Own(own) => own.out.is_some(),
        }
    }
}

// A NOTE ON WHAT IS NOT HERE, because it was built, measured and taken out
// again on 20 Sep 2026, and the next reader will think of it too.
//
// Draining the queue from the FRONT is what makes `close` archive order,
// and a worker further down the queue that has already answered is idle
// until the front retires. Freeing such a worker early - a `try_recv`
// sweep over the queue, each answer parked beside its member until its
// turn to close - is the repair that suggests itself, and it is WRONG: a
// worker's answer carries the CALLER'S WRITER back, and a member whose
// `close` has not been called is a member whose output the caller still
// holds open. Freeing the worker without closing the member therefore
// raises the outputs open at once above the worker count, which is the
// promise `Driver::open` makes in as many words. Both
// `several_members_are_open_for_writing_at_once` and
// `the_policy_caps_the_members_in_flight` failed on it at once, which is
// what they are for.
//
// It buys nothing even where it is legal, either: the budget it would
// have to respect is OUTPUTS, and a member taken early still has its
// output open, so there is no room behind it for another member. What the
// idle worker costs is real; what it would need is a member whose output
// is nothing at all (`Disposition::Verify`), or a pool that may close out
// of archive order, which spec F 3.7.6 forbids.
//
// 22 Sep 2026: it IS here now, and ON by default, because the
// other half of that sentence was priced and turned out to be the whole
// of `f/extract-par-src4k-m3`'s gap: raise the OUTPUTS bound above the
// breadth (at most `factor` times it, twice by default) while the members
// DECODING at once stay at most the breadth, and an answered worker takes
// the next member while its own waits to close in order. The promise the
// two tests hold moved with it, to twice the breadth, and
// `OUTPUTS_OVER_BREADTH_ENV` at 1 gives back the pool described above.

/// The concurrent driver.
pub(crate) struct Pool<'scope, 'env, S: ParallelSink> {
    pub(super) sink: &'env S,
    pub(super) scope: &'scope Scope<'scope, 'env>,
    pub(super) policy: MemoryPolicy,
    pub(super) cancel: Option<Arc<AtomicBool>>,
    /// The workers, SPAWNED ON FIRST USE.
    ///
    /// Lazily, and it is measured: an archive whose members are all below
    /// the offload floor uses no worker at all, and spawning eight threads
    /// and joining them for it is pure cost. On the 20,000 member stored
    /// leg, where the floor keeps every member on the walking thread, a
    /// pool that spawned up front read 0.883x against the old engine at
    /// width 8 and 0.917x at width 1 - a width the leg does not use -
    /// where the sequential path on the same corpus reads 0.958x. A thread
    /// this operation never gives work to is a thread it should not have.
    pub(super) hands: Vec<Option<Hand<'scope, S::Out>>>,
    /// Workers holding nothing.
    pub(super) free: Vec<usize>,
    /// Members dispatched and not yet closed, oldest first. Draining from
    /// the front IS archive order; nothing else here orders anything.
    pub(super) flight: VecDeque<Flight<S::Out>>,
    /// The outputs open at once, as a multiple of the breadth
    /// ([`OUTPUTS_OVER_BREADTH_ENV`]); 2 by default, 1 the tighter pool.
    pub(super) outputs_factor: usize,
    /// An answer parked in `flight` ends the operation. Nothing more is
    /// dispatched once one is seen: the queue is closed up to it instead.
    pub(super) fatal_parked: bool,
    /// Name buffers back from closed members.
    pub(super) spare_names: Vec<Vec<u8>>,
    /// Chunk buffers no pipe worker holds.
    pub(super) spare: Vec<Vec<u8>>,
    pub(super) closed: Closed,
    pub(super) limit: u64,
    /// Under a NAMED budget (`extract::budget_floor`): the engine memory
    /// left for the windows of the members in flight beside what the walk
    /// holds whatever the member, which the DECLARED charges are priced
    /// against; and the operation's LIVE charges (`memory::op_current`)
    /// are priced against `limit` itself. Under the whole-process default
    /// (`MemoryPolicy::keeps_residency`, no pre-scan) the room is `limit`
    /// itself, so the declared arm is the old check and the live arm is
    /// what is added. `None` for the engine's own default, where the
    /// declared charges alone are priced against `limit`, as before.
    pub(super) room: Option<u64>,
    pub(super) solid_archive: bool,
    /// The lanes the members decoding at once share, when the
    /// arrangement is the reservation rather than the division.
    pub(super) budget: Option<Arc<crate::read::lanes::LaneBudget>>,
    /// Whether the caller STATED the width, which the tape's own lane
    /// default reads (`rar5_lz::tape::workers`).
    pub(super) width_stated: bool,
    /// The read's width, `ReadOptions::workers` as it resolved (8.4.2).
    /// The ceiling the breadth and the lanes are spent against; the
    /// policy beside it is MEMORY and bounds neither.
    pub(super) width: usize,
    /// The breadth the LATE narrowing falls back to, once the walk has
    /// shown there are members enough to fill it. `read::lanes`.
    pub(super) narrowed: usize,
    /// How many dispatched members it takes to narrow, or `None` for the
    /// arrangement that never does. See `narrow_after`.
    pub(super) narrow_after: Option<usize>,
    /// Members this pool has dispatched, ever. The only count of the
    /// archive the pool has before the walk ends, and it only ever
    /// grows.
    pub(super) dispatched: usize,
    /// Small member batches, when `RARKIT_SMALL_BATCH` asks for them.
    pub(super) batch: Option<SmallBatch>,
    /// The member team's width cap, `RARKIT_SMALL_TEAM`; 0 is none.
    pub(super) small_team: usize,
    /// x86-64: the most workers the member team may hold whatever the
    /// breadth ([`small_team_room`]).
    #[cfg(target_arch = "x86_64")]
    pub(super) team_room: usize,
    /// x86-64: whether the batches take written members too
    /// ([`small_batch_named`]).
    #[cfg(target_arch = "x86_64")]
    pub(super) batch_named: bool,
    /// The batch being filled: its members are in `flight` already and
    /// its worker reserved, but nothing is sent until it is full or the
    /// walk must wait on anything ([`Pool::flush`]).
    pub(super) filling: Option<Filling<S::Out>>,
    /// Whether a member the walk handled is queued for its turn
    /// ([`QUEUE_OWN_ENV`]).
    pub(super) queue_own: bool,
    /// The most members waiting to close under `queue_own`.
    pub(super) queue_cap: usize,
    /// Members in `flight` holding the caller's writer.
    pub(super) writing: usize,
    /// Those of them a worker is still decoding: the writers BEING
    /// WRITTEN, which the outputs bound holds whatever waits behind them.
    pub(super) being_written: usize,
    /// How many further writers may wait to close under `queue_own`
    /// (`ReadOptions::waiting_outputs`); 0 is the one bound for all.
    pub(super) waiting: usize,
    /// Whether the ready front is closed at every offer
    /// ([`CLOSE_READY_ENV`]).
    pub(super) close_ready: bool,
    /// What every worker tells this walk beside its answers.
    pub(super) notes: Notes,
    /// How many members have left the front of `flight`, ever: the number
    /// of the member now at its front, so a member's number less this is
    /// its place.
    pub(super) closed_before: usize,
    /// The members a worker is still decoding, by number, oldest first.
    ///
    /// The flight is searched for them at every member (how many workers
    /// are busy, whose answer has arrived), and under [`QUEUE_OWN_ENV`] it
    /// is thousands of entries long while these are at most a breadth of
    /// workers' worth. Walking the whole flight for them cost a
    /// 20,000-member archive 3.7 times its instructions (counted on
    /// a gate box at `-mt2`, 1 Oct 2026),
    /// so they are kept here.
    pub(super) pending: VecDeque<usize>,
    /// The worker writing the member the walk is decoding, from that
    /// member's `open` until its `close` takes the worker's answer. Still
    /// set at the next `open` only for a member closed with no writer
    /// (`extract::refuse`), whose answer is taken there
    /// ([`Pool::take_back_the_pipe`]).
    pub(super) piped: Option<usize>,
}

/// A small member batch not yet sent.
pub(super) struct Filling<W> {
    pub(super) worker: usize,
    pub(super) jobs: Vec<Job<PoolOut<W>>>,
    pub(super) bytes: u64,
    pub(super) width: usize,
    pub(super) exact: bool,
}

impl<'scope, 'env, S: ParallelSink> Pool<'scope, 'env, S>
where
    'env: 'scope,
{
    pub(super) fn new(
        scope: &'scope Scope<'scope, 'env>,
        sink: &'env S,
        workers: usize,
        opts: &ReadOptions,
    ) -> Pool<'scope, 'env, S>
    where
        S::Out: 'env,
    {
        let mut hands = Vec::with_capacity(workers);
        hands.resize_with(workers, || None);
        let batch = small_batch();
        Pool {
            batch,
            small_team: small_team(),
            #[cfg(target_arch = "x86_64")]
            team_room: small_team_room(),
            #[cfg(target_arch = "x86_64")]
            batch_named: small_batch_named(),
            filling: None,
            queue_own: queue_own(),
            queue_cap: queue_own_cap(),
            writing: 0,
            being_written: 0,
            waiting: opts.waiting_outputs.unwrap_or(0),
            close_ready: close_ready_env(),
            closed_before: 0,
            pending: VecDeque::with_capacity(workers * 2),
            piped: None,
            // The pool is made on the thread that walks.
            notes: Notes {
                failed: Arc::new(AtomicBool::new(false)),
                walker: wait_any().then(std::thread::current),
            },
            sink,
            scope,
            policy: opts.memory,
            cancel: opts.cancel.clone(),
            hands,
            free: (0..workers).rev().collect(),
            flight: VecDeque::with_capacity(workers * outputs_over_breadth()),
            outputs_factor: outputs_over_breadth(),
            fatal_parked: false,
            spare_names: Vec::with_capacity(workers),
            spare: Vec::with_capacity(workers * DEPTH),
            closed: Closed::default(),
            limit: opts.memory.working_limit,
            room: None,
            solid_archive: false,
            width: opts.read_width(),
            width_stated: opts.workers.is_some(),
            narrowed: crate::read::lanes::useful_breadth(opts.read_width(), workers),
            narrow_after: narrow_after(),
            dispatched: 0,
            budget: shrinking().then(|| {
                Arc::new(
                    crate::read::lanes::LaneBudget::with_spill(opts.read_width(), spilling())
                        .asked(workers)
                        .abreast_on(crate::read::lanes::abreast_cores(opts.workers.is_some())),
                )
            }),
        }
    }

    /// The tape lanes one member may open, dispatched into this pool now.
    ///
    /// **This is the whole of the breadth-against-width question, and it
    /// is one line of arithmetic.** API 8.2's row for 8.3 gives the
    /// ceiling as "at most `max_workers` decode units over all members
    /// together", and 8.3 itself as the PRODUCT of the members decoded at
    /// once and the width inside each of them. Before this existed the
    /// pool budgeted breadth only: a dispatched member carried the
    /// operation's whole policy, so `tape::workers` minned against the
    /// full `max_workers` and breadth 8 at a ceiling of 8 ran 64 tape
    /// lanes, measured. The product is what the ceiling bounds, so the
    /// product is what is divided here.
    ///
    /// **Divided against the POOL'S WIDTH, and the alternative is unsound
    /// rather than merely slower.** Dividing against the members in
    /// FLIGHT is the arrangement that suggests itself, because it lets a
    /// member dispatched into a quiet pool take every lane. It does not
    /// hold: a member keeps the width it was granted for its whole
    /// decode, so a grant made while the pool was quiet is still
    /// outstanding when the pool fills, and the ceiling is breached again.
    /// Measured at arm 3 of the breadth driver script: 16 lanes alive at
    /// a ceiling of 8. Capping each grant by the lanes already granted
    /// does not rescue it either, because the slots still free must each
    /// keep a lane in reserve, and once they do the arithmetic collapses
    /// back into this line: members in flight, plus this one, plus the
    /// slots still free, IS the pool's width.
    ///
    /// What would rescue it is a member handing lanes BACK as its
    /// neighbours finish, which the tape path could do cheaply since it
    /// re-sizes its lanes once per chunk. That is worth building only if
    /// the width inside a member is worth having, and arm 3 is kept in
    /// the harness, unsound, precisely to put an upper bound on that. The
    /// measured table is what decided it.
    pub(super) fn inner_width(&self) -> usize {
        let ceiling = self.width.max(1);
        if self.budget.is_some() {
            // The budget decides, once per chunk, and a member that asks
            // for the ceiling gets whatever of it is free.
            return ceiling;
        }
        // The pool's own width: every slot either holds a member, is this
        // dispatch, or is free for one, so this is the most members that
        // can be decoding at once and the breadth the product is against.
        let width = ceiling / self.hands.len().max(1);
        #[cfg(feature = "breadth-knob")]
        let width = match crate::probe::breadth_arm() {
            crate::probe::BREADTH_ARM_WHOLE => ceiling,
            crate::probe::BREADTH_ARM_BREADTH_FIRST => 1,
            // Counting THIS member, which is not in `flight` yet. Kept
            // for measurement only; see the note above on why it is not
            // the arrangement that ships.
            crate::probe::BREADTH_ARM_HANDBACK => ceiling / self.flight.len().saturating_add(1),
            _ => width,
        };
        // Never below one: a member decoded at width zero is a member not
        // decoded, and 8.3 leaves every member at least a width of one.
        // The breadth is itself at most the ceiling (`extract_parallel_with`
        // mins the caller's request against it), so flooring here can put
        // at most `ceiling` lanes in the air, never more.
        width.max(1)
    }

    /// The members this pool will keep in flight at once, RIGHT NOW.
    ///
    /// The pool's slot count until the walk has offered more members
    /// than `narrow_after`, and the narrowed breadth from then on. Every
    /// place that waits for room waits on this rather than on a free
    /// slot, so retiring slots needs no second mechanism: a slot above
    /// the breadth simply never has a member sent to it, and the
    /// reservation in `read::lanes` divides the ceiling by the members
    /// actually live, so the width inside each of them widens by itself.
    ///
    /// It only ever falls, and it falls once. A breadth that could rise
    /// again would hand a member a slot the budget has already promised
    /// as lanes elsewhere.
    pub(super) fn breadth(&self) -> usize {
        match self.narrow_after {
            Some(after) if self.dispatched > after => self.narrowed,
            _ => self.hands.len(),
        }
        .max(1)
    }

    /// The worker in slot `at`, which [`Pool::start`] has started: every
    /// slot a member or a pipe is sent to was started when it was taken.
    pub(super) fn hand(&mut self, at: usize) -> &mut Hand<'scope, S::Out> {
        self.hands[at]
            .as_mut()
            .expect("a slot is started before anything is sent to it")
    }

    /// Start slot `at`'s worker if this is its first job. `false` when the
    /// host will not start the thread: the caller retires the slot, as the
    /// budget retires one it refuses, and the pool runs at the width it
    /// has (down to none, where the walk decodes every member itself).
    pub(super) fn start(&mut self, at: usize) -> bool {
        if self.hands[at].is_some() {
            return true;
        }
        let depth = self.batch.map_or(1, |b| b.members);
        self.hands[at] = spawn(
            self.scope,
            self.policy,
            self.cancel.clone(),
            self.budget.clone(),
            depth,
            self.width_stated,
            self.notes.clone(),
        );
        self.hands[at].is_some()
    }

    /// A free worker for a PIPE, started, or `None` when the pool has no
    /// worker left to give one and nothing in flight to wait for.
    pub(super) fn started_free_worker(&mut self) -> Result<Option<usize>> {
        loop {
            self.harvest();
            if self.free.is_empty() && self.flight.is_empty() {
                return Ok(None);
            }
            let worker = self.free_worker()?;
            if self.start(worker) {
                return Ok(Some(worker));
            }
            // Retired: the slot is never put back on the free list.
        }
    }

    /// What slot `at` has committed, which is nothing until it is spawned.
    pub(super) fn held(&self, at: usize) -> u64 {
        self.hands[at].as_ref().map_or(0, |hand| hand.held)
    }

    /// The working memory every worker holds together, as the pool has
    /// committed it.
    pub(super) fn committed(&self) -> u64 {
        self.hands
            .iter()
            .flatten()
            .fold(0u64, |sum, hand| sum.saturating_add(hand.held))
    }

    /// This worker's answer, WITHOUT parking for it where parking would
    /// cost more than the wait ([`SETTLE_SPIN_US`]).
    ///
    /// Nothing about the pool's arrangement changes here: the same answer
    /// comes from the same worker in the same order, and only the way of
    /// waiting for it is different.
    ///
    /// `None` is "this worker will never answer". A slot with a member in
    /// flight has been spawned by definition - the job was sent to it -
    /// so the empty slot below is unreachable and answers the same way a
    /// closed channel does, which is the only safe reading of either.
    pub(super) fn answer_of(&mut self, worker: usize) -> Option<Done<S::Out>> {
        self.answer_after(worker, settle_spin_us())
    }

    /// [`Self::answer_of`] with a sweep of `spin` microseconds before the
    /// park, 0 to park at once.
    pub(super) fn answer_after(&mut self, worker: usize, spin: u64) -> Option<Done<S::Out>> {
        let hand = self.hands[worker].as_ref()?;
        let mut sweep = super::super::spin::Spin::new(spin);
        loop {
            match hand.answers.try_recv() {
                Ok(done) => return Some(done),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return None,
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if sweep.over() {
                // Past the budget: parking is now the cheaper wait.
                #[cfg(feature = "test-support")]
                let parked = std::time::Instant::now();
                let answer = hand.answers.recv().ok();
                #[cfg(feature = "test-support")]
                crate::probe::note_walk_stall(parked.elapsed().as_nanos() as u64);
                return answer;
            }
            std::hint::spin_loop();
        }
    }

    /// Take a worker's answer, count what it says and close its member.
    ///
    /// This is the ONE place a dispatched member reaches the caller, and
    /// it is called from the FRONT of the queue, so the order a caller sees
    /// is the order the walk pushed - archive order - whatever order the
    /// workers finished in.
    pub(super) fn settle_front(&mut self) -> Result<()> {
        self.flush();
        #[cfg(feature = "wait-census")]
        let census = crate::probe::census::at_settle();
        let Some(front) = self.flight.pop_front() else {
            return Ok(());
        };
        if front.decoding().is_some() {
            // Still decoding, so the oldest of them: its number is the
            // front's.
            let oldest = self.pending.pop_front();
            debug_assert_eq!(oldest, Some(self.closed_before));
        }
        self.closed_before += 1;
        if front.writes() {
            self.writing -= 1;
            if front.decoding().is_some() {
                self.being_written -= 1;
            }
        }
        let front = match front {
            Flight::Sent(sent) => *sent,
            Flight::Own(own) => return self.close_own(*own),
        };
        let Sent {
            file,
            data,
            worker,
            answer,
            ..
        } = front;
        let done = match answer {
            // Harvested earlier: its worker is already free and its
            // working figure already noted.
            Some(done) => done,
            None => {
                let Some(done) = self.answer_of(worker) else {
                    // A worker that ended without answering has panicked;
                    // the scope will re-raise it. Nothing here invents an
                    // outcome for a member whose decode it cannot account
                    // for.
                    return Err(Error::new(ErrorKind::Corrupt(
                        crate::error::Corruption::Stream,
                    )));
                };
                self.answered(worker, done.working);
                done
            }
        };
        #[cfg(feature = "wait-census")]
        drop(census);
        let Done {
            out,
            bytes,
            checksum_ok,
            error,
            fatal,
            yielded,
            name,
            mismatches,
            spare,
            ..
        } = done;
        for buf in spare {
            if self.spare.len() < self.spare.capacity() {
                self.spare.push(buf);
            }
        }
        // An error that ends the whole operation ends it here, with no
        // `close` - exactly as the sequential path returns one out of
        // `member()` without closing. A DECODER's verdict on one member's
        // bytes is not one of those: it is reported below.
        if fatal {
            self.recycle(name);
            // The walk's error, returned when the pool has settled, is
            // this member's too (`Done::yielded`).
            if yielded {
                return Ok(());
            }
            return Err(error.expect("a fatal answer carries its error"));
        }
        let outcome = MemberOutcome {
            checksum_ok,
            bytes,
            password_refused: crate::read::password_refused(error.as_ref()),
            fragment_mismatches: u32::try_from(mismatches.len()).unwrap_or(u32::MAX),
        };
        self.count(&outcome, bytes);
        let info = extract::info_of(&name, &file, &data);
        let mut result = Ok(());
        for &volume in &mismatches {
            result = self.sink.fragment_mismatch(&info, volume);
            if result.is_err() {
                break;
            }
        }
        let result = result.and_then(|()| self.sink.close(&info, out, &outcome));
        self.recycle(name);
        if self.closed.deferred.is_none() {
            self.closed.deferred = error;
        }
        result
    }

    /// Take a worker's report of what it now holds.
    ///
    /// It raises the worker's COMMITMENT as well as its last figure, and
    /// that is the point. `window_of` commits a member to what a RAR 5
    /// decoder will hold for it (its ring at the member's reach, its packed
    /// buffer and the read window), which is what the pool can know before
    /// the decoder exists - but a decoder can hold more than that: spec
    /// I's text model arena, spec H1's tables and this driver's own
    /// scratch and read window all sit beside it, and for a RAR 3 member
    /// the arena alone can rival the window. Committing only the declared
    /// figure therefore lets a second member in beside a first that is
    /// already over budget, and `f_extract_parallel` found exactly that as
    /// an out-of-memory on its first campaign. From a worker's first
    /// answer onwards the budget is measured and not declared.
    /// One answer taken from `worker`: note what it holds, and free it
    /// once it owes nothing more.
    pub(super) fn answered(&mut self, worker: usize, working: u64) {
        self.note_working(worker, working);
        let hand = self.hand(worker);
        hand.owed = hand.owed.saturating_sub(1);
        if hand.owed == 0 {
            self.free.push(worker);
        }
    }

    /// Send the batch being filled, if there is one.
    ///
    /// Called before anything that WAITS on a member in flight: a member
    /// in an unsent batch has no worker decoding it, and waiting for its
    /// answer would wait for ever.
    pub(super) fn flush(&mut self) {
        let Some(Filling {
            worker,
            jobs,
            bytes,
            width,
            exact,
        }) = self.filling.take()
        else {
            return;
        };
        #[cfg(feature = "test-support")]
        crate::probe::note_batch(jobs.len(), bytes);
        let _ = bytes;
        if self
            .hand(worker)
            .tasks
            .send(Task::Batch { jobs, width, exact })
            .is_err()
        {
            unreachable!("a worker outlives the pool that owns it");
        }
    }

    pub(super) fn note_working(&mut self, worker: usize, working: u64) {
        let hand = self.hand(worker);
        hand.working = working;
        // What the worker holds NOW (see `sequential`'s `answered`).
        hand.held = working;
    }

    pub(super) fn count(&mut self, outcome: &MemberOutcome, bytes: u64) {
        self.closed.members += 1;
        self.closed.bytes += bytes;
        if outcome.checksum_ok == Some(false) {
            self.closed.checksum_failures += 1;
        }
    }

    pub(super) fn recycle(&mut self, name: Vec<u8>) {
        if self.spare_names.len() < self.spare_names.capacity() {
            self.spare_names.push(name);
        }
    }

    /// A worker holding nothing, waiting - by closing the oldest member in
    /// flight - until there is one.
    ///
    /// A worker is either free, in the queue, or holding the pipe of the
    /// one member the walk is decoding, so an empty queue with no free
    /// worker means the caller is asking for a second pipe while the first
    /// is open, which the walk never does: it closes each member before it
    /// opens the next.
    pub(super) fn free_worker(&mut self) -> Result<usize> {
        self.harvest();
        while self.free.is_empty() {
            if self.flight.is_empty() {
                return Err(Error::new(ErrorKind::LimitExceeded {
                    resource: crate::Resource::Workers,
                    needed: 1,
                    limit: 0,
                }));
            }
            self.settle_front()?;
        }
        Ok(self.free.pop().expect("just made sure"))
    }

    /// The members this pool may hold OPEN at once: the breadth, times
    /// [`OUTPUTS_OVER_BREADTH_ENV`]'s factor, 2 by default.
    pub(super) fn outputs(&self) -> usize {
        self.breadth().saturating_mul(self.outputs_factor).max(1)
    }

    /// Whether the flight is at its bound, so that the front member must
    /// close before another is opened.
    ///
    /// The members waiting to close, against the outputs bound. Under
    /// [`QUEUE_OWN_ENV`] the bound counts what it promises, the members
    /// holding the caller's WRITER: a member that goes nowhere (`t`) or
    /// was skipped holds none, and a run of them behind one large member
    /// is what the queue exists to let the walk pass. Their number is
    /// held by [`QUEUE_OWN_CAP`] instead.
    ///
    /// **And a writer that only WAITS TO CLOSE may be counted apart**
    /// (SPEC-API section 4, "Outputs open at once"). With the queue on,
    /// `x` of the gate's binary set waited at this bound for 96 percent of
    /// the run with 60 of 64 workers idle: the flight filled with small
    /// members already written, behind one large member still decoding.
    /// Where the caller states an allowance for such writers
    /// (`ReadOptions::waiting_outputs`), the bound holds the writers
    /// still being written and the allowance holds the rest.
    pub(super) fn full(&self) -> bool {
        if self.queue_own {
            // The writers still being written against the bound itself;
            // every writer, the ones only waiting to close among them,
            // against the bound and the caller's allowance for waiting
            // ones together (`ReadOptions::waiting_outputs`, none unless
            // the caller states it).
            self.being_written >= self.outputs()
                || self.writing >= self.outputs().saturating_add(self.waiting)
                || self.flight.len() >= self.queue_cap
        } else {
            self.flight.len() >= self.outputs()
        }
    }

    /// Park a worker's answer beside its member `at` in the flight: its
    /// writer is no longer being written, only waiting to close.
    pub(super) fn park(&mut self, at: usize, done: Done<S::Out>) {
        if self.flight[at].decoding().is_some_and(|sent| sent.writes) {
            self.being_written -= 1;
        }
        let number = self.closed_before + at;
        if let Some(i) = self.pending.iter().position(|&n| n == number) {
            self.pending.remove(i);
        }
        self.flight[at].answer(done);
    }

    /// Put a member a worker will decode at the back of the flight.
    pub(super) fn send(&mut self, sent: Sent<S::Out>) {
        self.writing += usize::from(sent.writes);
        self.being_written += usize::from(sent.writes);
        self.pending
            .push_back(self.closed_before + self.flight.len());
        self.flight.push_back(Flight::Sent(Box::new(sent)));
    }

    /// The members a worker is still decoding, oldest first, each with
    /// its place in the flight.
    pub(super) fn decoding_members(
        &self,
    ) -> impl Iterator<Item = (usize, &Sent<S::Out>)> + use<'_, 'scope, 'env, S> {
        self.pending.iter().filter_map(move |&number| {
            let at = number - self.closed_before;
            self.flight[at].decoding().map(|sent| (at, sent))
        })
    }

    /// Close a member the walk handled, at its turn ([`Own`]): what
    /// [`Pool::close`] and [`Pool::skipped`] do at once on an empty
    /// flight, in the same order.
    pub(super) fn close_own(&mut self, own: Own<S::Out>) -> Result<()> {
        let Own {
            info,
            name,
            target,
            out,
            outcome,
            err,
            skipped,
        } = own;
        if skipped {
            self.closed.skip(&outcome, err);
            self.recycle(name);
            return Ok(());
        }
        self.count(&outcome, 0);
        let result = {
            let info = crate::read::attached(&info, &name, target.as_deref());
            self.sink.close(&info, out, &outcome)
        };
        self.recycle(name);
        if self.closed.deferred.is_none() {
            self.closed.deferred = err;
        }
        result
    }

    /// Queue a member the walk handled behind the members in flight.
    pub(super) fn queue(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<S::Out>,
        outcome: &MemberOutcome,
        err: Option<Error>,
        skipped: bool,
    ) {
        let mut name = self.spare_names.pop().unwrap_or_default();
        name.clear();
        name.extend_from_slice(member.name);
        let (info, target) = crate::read::detached(member);
        self.writing += usize::from(out.is_some());
        self.flight.push_back(Flight::Own(Box::new(Own {
            info,
            name,
            target,
            out,
            outcome: *outcome,
            err,
            skipped,
        })));
    }

    /// Members in flight whose worker is still decoding them.
    ///
    /// Counted in WORKERS: a batch's members are one worker's, and it is
    /// workers the breadth bounds. A batch's members sit together in the
    /// queue, so a change of worker is a new one.
    pub(super) fn decoding(&self) -> usize {
        let mut last = None;
        let mut n = 0;
        for (_, f) in self.decoding_members() {
            if last != Some(f.worker) {
                n += 1;
                last = Some(f.worker);
            }
        }
        n
    }

    /// The member team's width: the workers members below the offload
    /// floor may hold at once, at most the breadth.
    #[cfg(not(target_arch = "x86_64"))]
    pub(super) fn team(&self) -> usize {
        match self.small_team {
            0 => self.breadth(),
            n => n.min(self.breadth()),
        }
        .max(1)
    }

    /// The member team's width: the workers members below the offload
    /// floor may hold at once, at most the breadth, and on
    /// x86-64 at its default at most half the box's hardware threads
    /// ([`small_team_room`]).
    #[cfg(target_arch = "x86_64")]
    pub(super) fn team(&self) -> usize {
        team_width(self.small_team, self.breadth(), self.team_room)
    }

    /// Workers holding a member below the floor that has not answered,
    /// counted as `decoding` counts: a batch's members sit together.
    pub(super) fn team_busy(&self) -> usize {
        let mut last = None;
        let mut n = 0;
        for (_, f) in self.decoding_members().filter(|(_, f)| f.below) {
            if last != Some(f.worker) {
                n += 1;
                last = Some(f.worker);
            }
        }
        n
    }

    /// Wait until the member team has room: the oldest team member still
    /// decoding is the one waited for, and its answer is parked beside it.
    pub(super) fn wait_for_the_team(&mut self) -> Result<()> {
        self.flush();
        self.harvest();
        if self.team_busy() < self.team() {
            return Ok(());
        }
        let Some(worker) = self
            .decoding_members()
            .find(|(_, f)| f.below)
            .map(|(_, f)| f.worker)
        else {
            return Ok(());
        };
        // The oldest unanswered member of THIS worker is the one its next
        // answer belongs to, and a batch's members sit together.
        let at = self
            .decoding_members()
            .find(|(_, f)| f.worker == worker)
            .map(|(at, _)| at)
            .expect("just found one");
        #[cfg(feature = "wait-census")]
        let census = crate::probe::census::at(crate::probe::census::WALK_TEAM);
        let Some(done) = self.answer_of(worker) else {
            return Err(Error::new(ErrorKind::Corrupt(
                crate::error::Corruption::Stream,
            )));
        };
        #[cfg(feature = "wait-census")]
        drop(census);
        self.fatal_parked |= done.fatal;
        self.answered(worker, done.working);
        self.park(at, done);
        Ok(())
    }

    /// Take every answer that has ARRIVED, without waiting, and free its
    /// worker. The answer stays beside its member for that member's turn
    /// to close; nothing is closed here, so archive order is untouched.
    ///
    /// A no-op at a factor of 1, where a worker is freed only by its
    /// member's close.
    pub(super) fn harvest(&mut self) {
        if self.outputs_factor <= 1 {
            return;
        }
        // A worker's answers come in the order of its members, so once one
        // of its members has found nothing, its LATER members must not
        // look: an answer arriving between the two looks is the earlier
        // member's, and a batch puts several of one worker's members here.
        let mut empty: u64 = 0;
        // Over the members still decoding alone, oldest first: parking an
        // answer takes its member out of them, so the place is not
        // stepped past then.
        let mut i = 0;
        while i < self.pending.len() {
            let at = self.pending[i] - self.closed_before;
            let Some(worker) = self.flight[at].decoding().map(|f| f.worker) else {
                i += 1;
                continue;
            };
            let bit = 1u64 << (worker % 64);
            if empty & bit != 0 {
                i += 1;
                continue;
            }
            let Some(hand) = self.hands[worker].as_ref() else {
                i += 1;
                continue;
            };
            let Ok(done) = hand.answers.try_recv() else {
                empty |= bit;
                i += 1;
                continue;
            };
            self.fatal_parked |= done.fatal;
            self.answered(worker, done.working);
            self.park(at, done);
        }
    }

    /// Wait until a worker is free, WITHOUT closing anything unless
    /// closing is what frees one: the oldest member still decoding is the
    /// one waited for, and its answer is parked beside it.
    pub(super) fn wait_for_a_worker(&mut self) -> Result<()> {
        self.flush();
        #[cfg(feature = "wait-census")]
        let census = crate::probe::census::at(crate::probe::census::WALK_WORKER);
        // Whichever worker answers FIRST is the one wanted, and it is
        // rarely the oldest: sweep every worker still decoding for the
        // same no-park budget the front's answer gets ([`SETTLE_SPIN_US`]),
        // and only then park on the oldest of them.
        let mut sweep = super::super::spin::Spin::new(settle_spin_us());
        loop {
            self.harvest();
            if !self.free.is_empty() && self.decoding() < self.breadth() {
                return Ok(());
            }
            if sweep.over() {
                break;
            }
            std::hint::spin_loop();
        }
        // Under `WAIT_ANY_ENV` the walk sleeps until ANY worker answers:
        // each unparks it after its answer, so an answer that lands
        // between the harvest and the park is not missed (the unpark is
        // kept for the next park). A factor of 1 harvests nothing and
        // keeps the wait on the oldest.
        while self.notes.walker.is_some() && self.outputs_factor > 1 {
            self.harvest();
            if !self.free.is_empty() && self.decoding() < self.breadth() {
                return Ok(());
            }
            let Some(oldest) = self.decoding_members().next().map(|(_, f)| f.worker) else {
                break;
            };
            // A worker that ended without answering has panicked and will
            // unpark nobody: the wait below, on its channel, says so.
            if self.hands[oldest]
                .as_ref()
                .is_none_or(|hand| hand.handle.is_finished())
            {
                break;
            }
            std::thread::park_timeout(std::time::Duration::from_millis(50));
        }
        let Some((at, worker)) = self.decoding_members().next().map(|(at, f)| (at, f.worker))
        else {
            // Every member in flight has answered, so every worker is
            // free already; only the outputs bound can be what is full.
            #[cfg(feature = "wait-census")]
            {
                drop(census);
                crate::probe::census::because(crate::probe::census::WALK_OUTPUTS);
            }
            let settled = self.settle_front();
            #[cfg(feature = "wait-census")]
            crate::probe::census::because(crate::probe::census::WALK_END);
            return settled;
        };
        // The sweep above was this wait's whole budget: park on the oldest
        // at once. The form that shipped before swept a second budget on
        // it first (`read::spin`, `legacy`).
        let spin = if super::super::spin::legacy() {
            settle_spin_us()
        } else {
            0
        };
        let Some(done) = self.answer_after(worker, spin) else {
            return Err(Error::new(ErrorKind::Corrupt(
                crate::error::Corruption::Stream,
            )));
        };
        self.fatal_parked |= done.fatal;
        self.answered(worker, done.working);
        self.park(at, done);
        Ok(())
    }

    /// Close the queue up to a parked answer that ends the operation, so
    /// the error surfaces in archive order and no further member is
    /// dispatched behind it. Nothing to do at a factor of 1.
    /// Close every member at the front of the queue that needs NO wait: a
    /// member the walk handled, or one whose worker has answered. In
    /// archive order, like every close, and it stops at the first member
    /// still decoding. Only under a stated allowance of waiting writers
    /// ([`CLOSE_READY_ENV`]).
    pub(super) fn close_ready(&mut self) -> Result<()> {
        if !(self.queue_own && self.close_ready && self.waiting > 0) {
            return Ok(());
        }
        self.harvest();
        while self
            .flight
            .front()
            .is_some_and(|front| front.decoding().is_none())
        {
            self.settle_front()?;
        }
        Ok(())
    }

    pub(super) fn close_up_to_a_parked_failure(&mut self) -> Result<()> {
        // A pool that queues seldom waits, so it seldom harvests: a
        // worker's failure is read from its flag instead, and the queue is
        // closed up to it.
        if self.queue_own && self.notes.failed.load(Ordering::Acquire) {
            self.fatal_parked = true;
        }
        while self.fatal_parked && !self.flight.is_empty() {
            self.settle_front()?;
        }
        Ok(())
    }

    /// Which free worker should take a member needing `window` bytes.
    ///
    /// The one already holding a window that large costs no allocation at
    /// all, which is spec F 7.3.5 applied across workers; failing that, the
    /// one holding the most, because growing the largest costs the least
    /// extra against the budget.
    pub(super) fn pick(&self, window: u64) -> usize {
        let mut best = 0usize;
        let mut best_held = None;
        for (slot, &worker) in self.free.iter().enumerate() {
            let held = self.held(worker);
            let better = match best_held {
                None => true,
                Some(current) => {
                    // A worker that already fits beats one that does not;
                    // between two that fit, the smaller; between two that
                    // do not, the larger.
                    match (current >= window, held >= window) {
                        (false, true) => true,
                        (true, false) => false,
                        (true, true) => held < current,
                        (false, false) => held > current,
                    }
                }
            };
            if better {
                best = slot;
                best_held = Some(held);
            }
        }
        best
    }
}
