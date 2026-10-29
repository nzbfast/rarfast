//! The pool as the walk's `Driver`.

use super::*;

impl<'scope, 'env: 'scope, S: ParallelSink> Pool<'scope, 'env, S> {
    /// Take the answer of a pipe worker whose member the walk closed with
    /// NO writer (`extract::refuse`: a wrong password, a chain with no
    /// head), so the worker is free again and the caller's writer it was
    /// given is dropped.
    ///
    /// Not at that member's `close`: the walk still holds the pipe's
    /// sending end there, and the worker answers only once it is dropped,
    /// so waiting there would wait for ever. By the next member's `open`
    /// the walk has let go of it, and the wait is for a worker that has
    /// nothing left to write.
    fn take_back_the_pipe(&mut self) {
        let Some(worker) = self.piped.take() else {
            return;
        };
        // A worker that ended without answering has panicked; the scope
        // re-raises it, and its slot stays out of the free list.
        let Ok(done) = self.hand(worker).answers.recv() else {
            return;
        };
        self.answered(worker, done.working);
        for buf in done.spare {
            if self.spare.len() < self.spare.capacity() {
                self.spare.push(buf);
            }
        }
    }
}

impl<'scope, 'env: 'scope, S: ParallelSink> Driver for Pool<'scope, 'env, S> {
    type Out = PoolOut<S::Out>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<PoolOut<S::Out>>> {
        self.take_back_the_pipe();
        // Room is made BEFORE the caller is asked for another writer, so
        // the number of outputs it holds open at once is at most the
        // OUTPUTS bound, `outputs()`, and not one more: twice the breadth
        // by default, the breadth itself at a factor of 1.
        // Every one of those outputs is a buffer the caller is keeping for
        // us, which is why the bound is a promise and not an accident of
        // timing. The breadth is the pool's slot count unless the late
        // narrowing has lowered it (`breadth`), and it only ever falls, so
        // the promise can only tighten.
        self.close_up_to_a_parked_failure()?;
        while self.full() && !self.flight.is_empty() {
            #[cfg(feature = "wait-census")]
            crate::probe::census::because(crate::probe::census::WALK_OUTPUTS);
            let settled = self.settle_front();
            #[cfg(feature = "wait-census")]
            crate::probe::census::because(crate::probe::census::WALK_END);
            settled?;
        }
        match self.sink.open(member)? {
            Disposition::Skip => Ok(Disposition::Skip),
            Disposition::Verify => Ok(Disposition::Verify),
            Disposition::Write(out) => {
                // A member this pool is about to take whole carries the
                // caller's writer untouched, because the worker that
                // decodes it will do the writing. A member the WALK will
                // decode has its writes piped to a worker instead - but
                // only if it is big enough to pay for one. Below the floor
                // the walk writes straight through, which is what it did
                // before any of this existed and what a 20,000 member
                // archive wants.
                // So does the FIRST fragment of a member split across
                // volumes of a kind the walk dispatches over its fragment
                // list (`extract::Split`, `extract::split_job_kind`); if it
                // does not, the walk writes it straight through as it
                // writes a small member.
                if extract::offloadable(
                    self.solid_archive,
                    member.solid,
                    member.split_before,
                    member.split_after,
                    member.unpacked_size,
                    member.packed_size,
                    &member.method,
                ) || !extract::worth_a_worker(member.unpacked_size, &member.method)
                    || (self.takes_split()
                        && member.split_after
                        && !member.split_before
                        && extract::split_job_kind(
                            matches!(member.method, crate::types::Method::Stored),
                            member.encrypted,
                        ))
                {
                    return Ok(Disposition::Write(PoolOut::Carried(out)));
                }
                // No worker the host would start: the walk writes straight
                // through, as it writes a member below the floor.
                let Some(worker) = self.started_free_worker()? else {
                    return Ok(Disposition::Write(PoolOut::Carried(out)));
                };
                let (tx, chunks) = sync_channel::<Vec<u8>>(DEPTH);
                let (ret, ret_rx) = sync_channel::<Vec<u8>>(DEPTH + 1);
                for _ in 0..DEPTH {
                    let buf = self
                        .spare
                        .pop()
                        .unwrap_or_else(|| Vec::with_capacity(CHUNK));
                    // The channel takes DEPTH + 1 and DEPTH are put in, so
                    // this never blocks.
                    let _ = ret.send(buf);
                }
                let refusal = Arc::new(Refusal::default());
                self.hand(worker).owed = 1;
                self.piped = Some(worker);
                if self
                    .hand(worker)
                    .tasks
                    .send(Task::Pipe {
                        out,
                        chunks,
                        ret,
                        refusal: Arc::clone(&refusal),
                    })
                    .is_err()
                {
                    unreachable!("a worker outlives the pool that owns it");
                }
                Ok(Disposition::Write(PoolOut::Piped(Handoff {
                    tx: Some(tx),
                    ret: ret_rx,
                    current: None,
                    worker,
                    refusal,
                })))
            }
        }
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<PoolOut<S::Out>>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        // Everything the walk handed to a worker is ahead of this member in
        // archive order, so it is closed first. That is the whole of the
        // ordering argument.
        //
        // Under `QUEUE_OWN_ENV` it WAITS ITS TURN in that queue instead,
        // behind the members in flight, and the walk goes on. A member
        // whose writes were piped is settled here as before: its worker's
        // answer says whether the caller's writer refused a write, and a
        // refusal ends the run at this member, not some members later.
        if self.queue_own && !self.flight.is_empty() && !matches!(out, Some(PoolOut::Piped(_))) {
            self.flush();
            let out = match out {
                Some(PoolOut::Carried(w)) => Some(w),
                _ => None,
            };
            self.queue(member, out, outcome, err, false);
            return Ok(());
        }
        #[cfg(feature = "wait-census")]
        crate::probe::census::because(crate::probe::census::WALK_OWN_CLOSE);
        let settled = self.settle();
        #[cfg(feature = "wait-census")]
        crate::probe::census::because(crate::probe::census::WALK_END);
        settled?;
        let (out, write_error) = match out {
            Some(PoolOut::Carried(w)) => (Some(w), None),
            Some(PoolOut::Piped(mut handoff)) => {
                let worker = handoff.worker;
                self.piped = None;
                let _ = handoff.flush();
                // Dropping the sender is what tells the worker the member
                // has ended.
                handoff.tx = None;
                drop(handoff);
                let done = self.hand(worker).answers.recv().map_err(|_| {
                    Error::new(ErrorKind::Corrupt(crate::error::Corruption::Stream))
                        .with_member(member.name)
                })?;
                self.answered(worker, done.working);
                for buf in done.spare {
                    if self.spare.len() < self.spare.capacity() {
                        self.spare.push(buf);
                    }
                }
                (done.out, done.error)
            }
            None => (None, None),
        };
        // A write the caller's writer refused AFTER the walk's last write
        // into the pipe is known only now, from the worker's answer. It
        // ends the run as it does when the walk meets it at a write (and
        // as `emit` ends the sequential walk): raised, and the member
        // neither counted nor closed, because the outcome in hand is the
        // DECODE's and says nothing of bytes the writer did not take.
        if let Some(e) = write_error {
            return Err(e);
        }
        self.count(outcome, 0);
        let result = self.sink.close(member, out, outcome);
        // The walk counted this member's bytes itself, so nothing is added
        // for them here.
        if self.closed.deferred.is_none() {
            self.closed.deferred = err;
        }
        result
    }

    fn skipped(
        &mut self,
        member: &MemberInfo<'_>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        // What is in flight ahead of it is closed first, as for `close`, so
        // the deferred error stays the first in archive order. Under
        // `QUEUE_OWN_ENV` it is counted at its turn instead.
        if self.queue_own && !self.flight.is_empty() {
            self.flush();
            self.queue(member, None, outcome, err, true);
            return Ok(());
        }
        let _ = member;
        #[cfg(feature = "wait-census")]
        crate::probe::census::because(crate::probe::census::WALK_SKIPPED);
        let settled = self.settle();
        #[cfg(feature = "wait-census")]
        crate::probe::census::because(crate::probe::census::WALK_END);
        settled?;
        self.closed.skip(outcome, err);
        Ok(())
    }

    /// For a member the WALK decoded; this pool opened it with the caller
    /// already (`open` above), so the caller hears of it at once, on the
    /// walking thread, before the member's `close`.
    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.sink.fragment_mismatch(member, volume)
    }

    fn offloads(&self) -> bool {
        true
    }

    /// A member split across volumes goes to a worker over its fragment
    /// list (`extract::Split`): this pool never waits at a
    /// volume's end for the members in flight, so the walk can cross to
    /// the fragments it sends. Off only under the test knob that prices
    /// the old arrangement (`probe::set_split_jobs`).
    fn takes_split(&self) -> bool {
        #[cfg(feature = "test-support")]
        if let Some(on) = crate::probe::split_jobs() {
            return on;
        }
        true
    }

    fn batches_small(&self) -> bool {
        self.batch.is_some()
    }

    #[cfg(target_arch = "x86_64")]
    fn batches_written(&self) -> bool {
        self.batch_named
    }

    fn lane_budget(&self) -> Option<Arc<crate::read::lanes::LaneBudget>> {
        self.budget.clone()
    }

    fn note_solid(&mut self, solid: bool) {
        self.solid_archive = solid;
    }

    fn spare_name(&mut self) -> Vec<u8> {
        self.spare_names.pop().unwrap_or_default()
    }

    fn offer(&mut self, job: Job<PoolOut<S::Out>>) -> Result<Option<Job<PoolOut<S::Out>>>> {
        let window = extract::window_of(
            &job.codec,
            job.data.end - job.data.start,
            self.policy.max_window,
        );
        let declared = job.file.unpacked_size.unwrap_or(0);
        // A tape-path member's lanes hold tapes no window declares
        // ([`TAPE_RESERVE_PER_LANE`]).
        let window = if self.queue_own
            && self.policy.limit_named
            && self.width > 1
            && matches!(job.codec, extract::Codec::Rar5 { .. })
            && crate::rar5_lz::tape::workers(declared, self.width, self.width_stated) > 0
        {
            let most = crate::rar5_lz::tape::workers(declared, self.width, self.width_stated);
            let share = self.width / (self.decoding() + 1);
            let lanes = share.clamp(1, most.max(1)) as u64;
            window.saturating_add(lanes.saturating_mul(tape_reserve_per_lane()))
        } else {
            window
        };
        // A member larger than the cap alone is never a batch: it goes to
        // a worker by itself, so no batch ever holds more than its cap.
        let below = self.batch.is_some()
            && extract::batchable(
                self.solid_archive,
                job.file.solid,
                job.file.split_before,
                job.file.split_after,
                job.file.unpacked_size,
                job.data.end.saturating_sub(job.data.start),
                &job.file.method,
            );
        let small = self.batch.filter(|b| {
            declared <= b.cap
                && extract::batchable(
                    self.solid_archive,
                    job.file.solid,
                    job.file.split_before,
                    job.file.split_after,
                    job.file.unpacked_size,
                    job.data.end.saturating_sub(job.data.start),
                    &job.file.method,
                )
        });
        loop {
            // Room is the BREADTH's to give, not the slot count's: when
            // the walk has shown there are members enough to fill a
            // narrowed breadth, the slots above it are retired and this
            // is the one place that says so. With no narrowing in force
            // the breadth IS the slot count, and a flight as long as it
            // is exactly the "no free worker" this used to test.
            self.close_ready()?;
            self.close_up_to_a_parked_failure()?;
            if self.full() {
                #[cfg(feature = "wait-census")]
                crate::probe::census::because(crate::probe::census::WALK_OUTPUTS);
                let settled = self.settle_front();
                #[cfg(feature = "wait-census")]
                crate::probe::census::because(crate::probe::census::WALK_END);
                settled?;
                continue;
            }
            if let Some(filling) = &self.filling {
                // A small member joins the batch being filled when it fits
                // by count, by declared bytes and in the window its worker
                // already holds; anything else sends that batch first.
                let joins = small.is_some_and(|b| {
                    filling.jobs.len() < b.members
                        && filling.bytes.saturating_add(declared) <= b.cap
                        && window <= self.held(filling.worker)
                });
                if !joins {
                    self.flush();
                    continue;
                }
                let worker = filling.worker;
                let writes = matches!(job.out, Out::Write(_));
                self.send(Sent {
                    file: job.file.clone(),
                    data: job.data.clone(),
                    worker,
                    answer: None,
                    below: true,
                    writes,
                });
                self.dispatched += 1;
                self.hand(worker).owed += 1;
                let filling = self.filling.as_mut().expect("just matched");
                filling.jobs.push(job);
                filling.bytes += declared;
                if small.is_some_and(|b| filling.jobs.len() >= b.members) {
                    self.flush();
                }
                return Ok(None);
            }
            if self.free.is_empty() && self.flight.is_empty() {
                // Every slot retired because the host would start no thread
                // for it (`Pool::start`), and nothing in flight to free one:
                // the member goes back to the walk, which decodes it itself.
                return Ok(Some(job));
            }
            if self.outputs_factor > 1 {
                // The members DECODING at once stay at most the breadth
                // whatever the outputs bound is; only the members waiting
                // to close with their answer in hand sit above it.
                if self.free.is_empty() || self.decoding() >= self.breadth() {
                    self.wait_for_a_worker()?;
                    continue;
                }
            } else if self.free.is_empty() {
                #[cfg(feature = "wait-census")]
                crate::probe::census::because(crate::probe::census::WALK_WORKER);
                let settled = self.settle_front();
                #[cfg(feature = "wait-census")]
                crate::probe::census::because(crate::probe::census::WALK_END);
                settled?;
                continue;
            }
            if below && self.team_busy() >= self.team() {
                // The member team is full: wait for one of ITS workers,
                // however many others are free.
                self.wait_for_the_team()?;
                continue;
            }
            let slot = self.pick(window);
            let worker = self.free[slot];
            // The windows the workers hold are the operation's working
            // memory (SPEC-API 5.2), so a member whose window does not fit
            // BESIDE the others waits: the oldest member in flight is
            // closed, and this member takes a window already counted rather
            // than a new one on top. A member with nothing else in flight
            // is always allowed, because that is the sequential figure and
            // the policy has already refused a window above `max_window`.
            let mine = self.held(worker);
            let committed = self.committed();
            let charge = extract::charge_after(mine, window);
            let after = committed.saturating_sub(mine).saturating_add(charge);
            // Under a NAMED budget the member is priced twice, and must
            // fit both ways: its declared window beside the others' in
            // the room the walk's own holdings leave, and its declared
            // window on top of what the operation LIVE holds this
            // instant, against the limit itself. The live figure carries
            // what no declaration prices (a worker's scratch and read
            // window, the walk's ring and the seam's, the look-ahead's
            // chunks), and is what the ceiling is measured on (8.4.1).
            let (over, exact) = match self.room {
                Some(room) => {
                    let live = crate::memory::op_current();
                    let fits = |charge: u64| {
                        let after = committed.saturating_sub(mine).saturating_add(charge);
                        let after_live = live.saturating_sub(mine).saturating_add(charge);
                        after <= room && after_live <= self.limit
                    };
                    if fits(charge) {
                        (false, false)
                    } else if mine > window && fits(window) {
                        // The worker's kept ring is what does not fit:
                        // it is rebuilt at this member's reach instead
                        // (`Shrink::Exact`), and the member is charged
                        // at that.
                        (false, true)
                    } else {
                        (true, false)
                    }
                }
                None => (after > self.limit, false),
            };
            let charge = if exact { window } else { charge };
            let after = if exact {
                committed.saturating_sub(mine).saturating_add(charge)
            } else {
                after
            };
            // A worker already holding a window this large costs NOTHING
            // new, so it is never refused: refusing it once the measured
            // figures have carried `committed` past the limit left only an
            // empty flight able to take a member, and a pool of sixteen
            // 33 MiB workers under the default 512 MiB ran one member at
            // a time for the rest of the archive (measured on
            // Windows).
            if over && after > committed && !self.flight.is_empty() {
                // A slot NEVER SPAWNED that the budget refuses is retired,
                // not waited for. Settling the front here waited for the
                // OLDEST member to decode and close, and while a
                // never-spawned slot stayed on the free list the pool
                // never waited on whichever worker answered first
                // instead: at a width above what the budget holds, every
                // dispatch waited on the head of the queue. Counted on
                // the rivals' `c1` (2,571 members of 32 MiB under the
                // default 512 MiB): 2,555 of 2,571 dispatches refused at
                // every width from 17 up and none at 16, where the free
                // list empties and the pool waits on any worker. Retired,
                // a pool wider than its budget is the pool at the width
                // its budget holds (the width
                // cliff above sixteen). Nothing is admitted that was
                // refused before: the test above is unchanged, and a
                // retired slot only ever held nothing.
                if self.hands[worker].is_none() {
                    self.free.swap_remove(slot);
                    continue;
                }
                #[cfg(feature = "wait-census")]
                crate::probe::census::because(crate::probe::census::WALK_MEMORY);
                let settled = self.settle_front();
                #[cfg(feature = "wait-census")]
                crate::probe::census::because(crate::probe::census::WALK_END);
                settled?;
                continue;
            }
            if !self.start(worker) {
                // The host would not start this slot's thread: retired as a
                // budget-refused slot is, and the member tries another.
                self.free.swap_remove(slot);
                continue;
            }
            let width = self.inner_width();
            self.free.swap_remove(slot);
            self.hand(worker).held = charge;
            self.hand(worker).owed = 1;
            let writes = matches!(job.out, Out::Write(_));
            let flight = Sent {
                file: job.file.clone(),
                data: job.data.clone(),
                worker,
                answer: None,
                below,
                writes,
            };
            if let Some(b) = small {
                // The first member of a new batch: its worker is taken
                // now, and the batch is sent when full or when the walk
                // must wait ([`Pool::flush`]).
                self.send(flight);
                self.dispatched += 1;
                self.filling = Some(Filling {
                    worker,
                    jobs: vec![job],
                    bytes: declared,
                    width,
                    exact,
                });
                if b.members <= 1 || declared == b.cap {
                    self.flush();
                }
                return Ok(None);
            }
            if self
                .hand(worker)
                .tasks
                .send(Task::Decode {
                    job: Box::new(job),
                    width,
                    exact,
                })
                .is_err()
            {
                unreachable!("a worker outlives the pool that owns it");
            }
            self.send(flight);
            self.dispatched += 1;
            return Ok(None);
        }
    }

    fn settle(&mut self) -> Result<()> {
        self.flush();
        let mut first: Option<Error> = None;
        while !self.flight.is_empty() {
            if let Err(e) = self.settle_front() {
                if first.is_none() {
                    first = Some(e);
                }
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn closed(&mut self) -> Closed {
        let mut closed = std::mem::take(&mut self.closed);
        closed.working_memory = self
            .hands
            .iter()
            .flatten()
            .fold(0u64, |sum, hand| sum.saturating_add(hand.working));
        closed
    }
}
