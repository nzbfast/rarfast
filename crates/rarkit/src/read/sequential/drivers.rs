//! The look-ahead as the walk's `Driver`, shared and at home.

use super::*;

impl<'scope, 'env, 'k, K: Sink> Driver for Inner<'scope, 'env, 'k, K> {
    type Out = SeqOut<K::Out>;

    #[inline(always)]
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<SeqOut<K::Out>>> {
        self.skipped_here = false;
        // THE IDLE PATH. With nothing in the look-ahead a member goes ahead
        // only if it takes a worker and is not stored (`route`), so a
        // stored member, or a compressed one under the floor, is the
        // sequential path's member and nothing more: no answers to take,
        // no look-ahead to drain, no floor to read from the thread. An
        // archive of such members, 20,000 of 200 bytes, paid the whole
        // route a member for nothing (23 Sep 2026).
        if self.flight.is_empty() && self.stays_home(member) {
            return self.open_here(member);
        }
        self.open_routed(member)
    }

    #[inline(always)]
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<SeqOut<K::Out>>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        let current = std::mem::replace(&mut self.current, Current::None);
        if current == Current::Slot {
            return self.close_slot(out, outcome, err);
        }
        self.close_here(member, out, outcome, err)
    }

    /// Only a member `open` answered `Skip` for, which it never gives a
    /// slot: the caller's own answer, passed straight back.
    fn skipped(
        &mut self,
        _member: &MemberInfo<'_>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.current = Current::None;
        self.skipped_here = false;
        self.closed.skip(outcome, err);
        Ok(())
    }

    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        if self.current == Current::Slot {
            // The caller opens this member when it is delivered.
            self.mismatches.push(volume);
            return Ok(());
        }
        if self.skipped_here {
            // Closed as the skipped member it is (`close_here`).
            return Ok(());
        }
        self.sink.fragment_mismatch(member, volume)
    }
    fn note_solid(&mut self, solid: bool) {
        self.solid_archive = solid;
    }

    fn note_refused(&mut self) {
        if self.current == Current::Slot {
            if let Some(entry) = self.flight.back_mut() {
                entry.refused = true;
            }
        }
    }

    /// Only for the member `open` gave a slot: every other member runs on
    /// the walking thread whatever the walk would build, so the walk is
    /// not asked to test it for a worker and build a job to hand back.
    #[inline(always)]
    fn offloads(&self) -> bool {
        self.current == Current::Slot
    }

    /// A small member the look-ahead gave a slot is offered to a worker
    /// too ([`Inner::goes_small`]).
    fn batches_small(&self) -> bool {
        self.small
    }

    /// On x86-64 too, written or verified alike: what a worker writes here
    /// is the member's slot in memory, never the caller's writer, which is
    /// what was priced for the parallel pool's batches.
    #[cfg(target_arch = "x86_64")]
    fn batches_written(&self) -> bool {
        self.small
    }

    fn overlaps(&self) -> bool {
        true
    }

    fn lane_budget(&self) -> Option<Arc<crate::read::lanes::LaneBudget>> {
        self.budget.clone()
    }

    fn spare_name(&mut self) -> Vec<u8> {
        self.name_buf()
    }

    fn offer(&mut self, job: Job<SeqOut<K::Out>>) -> Result<Option<Job<SeqOut<K::Out>>>> {
        if !matches!(job.out, Out::Write(SeqOut::Ahead(_))) || self.current != Current::Slot {
            return Ok(Some(job));
        }
        // ALONE AND LAST: nothing is ahead of this member and nothing of
        // its volume follows it, so there is nothing for it to overlap
        // and the look-ahead would only add a copy. It runs as the
        // sequential path runs it, seam and all (measured: a lone 64 MiB
        // member taken ahead read 0.897x its own wall, untimed, an Apple M3 Mac,
        // 9 pairs).
        let alone = self.flight.len() == 1;
        let last = job
            .src
            .len()
            .is_some_and(|n| n.saturating_sub(job.data.end) <= LAST_TAIL);
        if alone && last {
            self.room_for_job(&job)?;
            return self.here(job).map(Some);
        }
        // LARGE, BARELY PACKED, LITTLE AHEAD OF IT AND LITTLE BEHIND: the
        // same member with a sample and a text file beside it
        // ([`goes_home`]). The members ahead of it are delivered first, in
        // order.
        if self.homes_large {
            let size = job.file.unpacked_size.unwrap_or(0);
            let packed = job.data.end.saturating_sub(job.data.start);
            let ahead = self.reserved.saturating_sub(size);
            let tail = job.src.len().map(|n| n.saturating_sub(job.data.end));
            if goes_home(size, packed, ahead, tail) || in_turn_at_home(self.narrow, size, packed) {
                return self.home_in_turn(job);
            }
        }
        let window = extract::window_of(
            &job.codec,
            job.data.end - job.data.start,
            self.policy.max_window,
        );
        if self.breadth == 0 {
            // Every worker's thread was refused (`Inner::start`): the walk
            // decodes each member itself, in its turn.
            return self.home_in_turn(job);
        }
        let mut exact;
        let worker = loop {
            let worker = self.free_worker()?;
            let mine = self.hands[worker].as_ref().map_or(0, |h| h.held);
            let declared = self
                .committed()
                .saturating_sub(mine)
                .saturating_add(self.ahead());
            let charge = mine.max(window);
            // A kept ring that no longer fits beside this member is rebuilt
            // at the member's reach (`Shrink::Exact`), and the member is
            // charged at that; only where even that does not fit does the
            // dispatch wait.
            exact = self.window_room.is_some()
                && mine > window
                && self.over_with(declared, mine, charge)
                && !self.over_with(declared, mine, window);
            let charge = if exact { window } else { charge };
            // Only a dispatch that ADDS window bytes waits for room: one
            // whose worker already holds a window this large adds nothing
            // to what is held, and refusing it collapsed the parallel
            // pool to a breadth of one wherever the workers' high-water
            // marks alone passed the limit (the Windows width work's
            // finding in `concurrent::Pool::offer`, 22 Sep 2026). The
            // look-ahead's own bytes are new memory and are counted in
            // `room` against what the windows leave under the limit.
            if self.over_with(declared, mine, charge) && window > mine {
                self.free.push(worker);
                if self.front_ready() {
                    self.deliver_front()?;
                    continue;
                }
                // Nothing to deliver yet: wait for a busy worker rather than
                // dispatch past the limit (8.4.1). With none busy there is
                // nothing to wait for. On the default path the member goes;
                // under a NAMED budget it goes HOME instead, to the walk,
                // which decodes it in order once what it holds live (its
                // own member on the seam, whose ring no worker's answer
                // frees) is done with: the sequential figure, which the
                // floor guarantees fits, never a second ring beside it
                // (counted on bin4g `p`).
                if self.await_answer()? {
                    continue;
                }
                if self.window_room.is_some() {
                    self.room_for_job(&job)?;
                    return self.here(job).map(Some);
                }
                let worker = self.free_worker()?;
                break worker;
            }
            break worker;
        };
        if !self.start(worker) {
            return self.home_in_turn(job);
        }
        let Job {
            src,
            data,
            file,
            name,
            format,
            out,
            codec,
            decryptor,
            keys,
            volume,
            in_set,
            split,
        } = job;
        let Out::Write(SeqOut::Ahead(mut boxed)) = out else {
            unreachable!("checked above");
        };
        let mut slot_out = boxed
            .take()
            .expect("a slot's writer is in its box until it is handed on");
        slot_out.waits = held_at_gate(
            file.unpacked_size.unwrap_or(0),
            data.end.saturating_sub(data.start),
        );
        self.spare_out = Some(boxed);
        let read = self.reads.begin(volume, data.start);
        let width = self.inner_width();
        let task = Task {
            job: Job {
                src,
                data,
                file,
                name,
                format,
                out: Out::Write(PoolOut::Carried(slot_out)),
                codec,
                decryptor,
                keys,
                volume,
                in_set,
                // Never a split member: this driver does not take one
                // (`Driver::takes_split`).
                split,
            },
            width,
            read,
            crc_on_deliver: self.flight.len() == 1,
            exact,
        };
        if let Some(entry) = self.flight.back_mut() {
            entry.crc_here = task.crc_on_deliver;
        }
        let hand = self.hands[worker].as_mut().expect("started above");
        hand.held = if exact { window } else { hand.held.max(window) };
        if hand.tasks.send(task).is_err() {
            unreachable!("a worker outlives the driver that owns it");
        }
        if let Some(entry) = self.flight.back_mut() {
            entry.state = State::Dispatched;
        }
        self.current = Current::None;
        Ok(None)
    }

    fn settle(&mut self) -> Result<()> {
        let mut first: Option<Error> = None;
        while let Some(front) = self.flight.front() {
            if self.failed || matches!(front.state, State::Opened) {
                let entry = self.flight.pop_front().expect("just seen");
                // The member the walk failed on had its `open` on the
                // sequential path before it failed, and the caller sees
                // the same here; nothing more, as there.
                if !self.failed && matches!(entry.state, State::Opened) && entry.pre.is_none() {
                    let _ = self.sink.open(&entry.info.view());
                }
                self.fail();
                self.abandon(&self.slots[entry.slot]);
                self.recycle_name(entry.info.name);
                continue;
            }
            if let Err(e) = self.deliver_front() {
                first.get_or_insert(e);
            }
        }
        self.reserved = 0;
        self.under_ceiling = 0;
        // Every worker's last answer, so the report's working memory is
        // what each one actually held and no decode outlives the settle.
        while self.free.len() < self.breadth {
            match self.recv_answer() {
                Some(a) => self.answered(a),
                None => break,
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn closed(&mut self) -> Closed {
        #[cfg(feature = "test-support")]
        crate::probe::note_seq_ahead_held(self.gate.peak());
        let mut closed = std::mem::take(&mut self.closed);
        closed.working_memory = self
            .hands
            .iter()
            .flatten()
            .fold(0u64, |sum, h| sum.saturating_add(h.working))
            .saturating_add(self.peak_reserved)
            .saturating_add(self.spares.held());
        closed
    }

    #[inline(always)]
    fn delivered(&self) -> u64 {
        self.delivered
    }
}

pub(super) type Shared<'scope, 'env, 'k, K> =
    std::rc::Rc<std::cell::RefCell<Inner<'scope, 'env, 'k, K>>>;

impl<K: Sink> Deliver for Shared<'_, '_, '_, K> {
    fn deliver_all(&self) -> Result<()> {
        self.borrow_mut().drain()
    }
}

/// The driver the walk holds: the shared state, borrowed for each call.
/// The walk never runs inside one of these calls, so the one other holder
/// of the cell, [`Held`] (called from inside the walk), never meets a
/// borrow already taken.
pub(crate) struct Ahead<'scope, 'env, 'k, K: Sink>(pub(super) Shared<'scope, 'env, 'k, K>);

impl<'scope, 'env, 'k, K: Sink> Driver for Ahead<'scope, 'env, 'k, K> {
    type Out = SeqOut<K::Out>;

    #[inline(always)]
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<SeqOut<K::Out>>> {
        self.0.borrow_mut().open(member)
    }

    #[inline(always)]
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<SeqOut<K::Out>>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.0.borrow_mut().close(member, out, outcome, err)
    }

    fn skipped(
        &mut self,
        member: &MemberInfo<'_>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.0.borrow_mut().skipped(member, outcome, err)
    }

    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.0.borrow_mut().fragment_mismatch(member, volume)
    }

    fn note_solid(&mut self, solid: bool) {
        self.0.borrow_mut().note_solid(solid);
    }

    fn note_refused(&mut self) {
        self.0.borrow_mut().note_refused();
    }

    #[inline(always)]
    fn offloads(&self) -> bool {
        self.0.borrow().offloads()
    }

    fn batches_small(&self) -> bool {
        self.0.borrow().batches_small()
    }

    #[cfg(target_arch = "x86_64")]
    fn batches_written(&self) -> bool {
        self.0.borrow().batches_written()
    }

    fn overlaps(&self) -> bool {
        true
    }

    fn lane_budget(&self) -> Option<Arc<crate::read::lanes::LaneBudget>> {
        self.0.borrow().lane_budget()
    }

    fn spare_name(&mut self) -> Vec<u8> {
        self.0.borrow_mut().spare_name()
    }

    fn offer(&mut self, job: Job<SeqOut<K::Out>>) -> Result<Option<Job<SeqOut<K::Out>>>> {
        self.0.borrow_mut().offer(job)
    }

    fn settle(&mut self) -> Result<()> {
        self.0.borrow_mut().settle()
    }

    fn closed(&mut self) -> Closed {
        self.0.borrow_mut().closed()
    }

    #[inline(always)]
    fn delivered(&self) -> u64 {
        self.0.borrow().delivered()
    }
}

/// The walk's first phase ([`extract_ahead`]): the caller's sink and nothing
/// between, as the sequential path's own driver, until a member reaches the
/// walk that the look-ahead could take.
///
/// **Why a phase and not a fast path.** The look-ahead's driver, even with
/// nothing in flight and every member settled in a few compares, costs the
/// walk its wrappers: the shared cell, the drop-behind observer, the writer
/// that can be a slot. On `f/test-rar4-20000-vsnull`, 20,000 stored members
/// of about 200 bytes, that was 585 instructions a member at an earlier revision and
/// still about 150 with every fast path (untimed, an Apple M3 Mac), 0.990x LEVEL
/// against the old engine on a second M3 Mac where the sequential path read
/// 1.033x in the same binary (23 Sep 2026). Here those members
/// run the sequential path's own code.
pub(super) struct Home<'k, K: Sink> {
    pub(super) sink: &'k mut K,
    pub(super) closed: Closed,
    /// The caller skipped a member that is not a directory: it is
    /// SELECTING, and the look-ahead takes nothing ahead for such a caller
    /// ([`Inner::route`]), so the walk never hands off.
    pub(super) selecting: bool,
    pub(super) floor_compressed: u64,
    /// Compressed members under that floor go ahead too
    /// ([`Inner::goes_small`]).
    pub(super) small: bool,
}

impl<K: Sink> Driver for Home<'_, K> {
    type Out = K::Out;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<K::Out>> {
        let disposition = self.sink.open(member)?;
        if matches!(disposition, Disposition::Skip) && !member.is_directory {
            self.selecting = true;
        }
        Ok(disposition)
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<K::Out>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.closed.members += 1;
        if outcome.checksum_ok == Some(false) {
            self.closed.checksum_failures += 1;
        }
        self.sink.close(member, out, outcome)?;
        if self.closed.deferred.is_none() {
            self.closed.deferred = err;
        }
        Ok(())
    }

    fn skipped(
        &mut self,
        _member: &MemberInfo<'_>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.closed.skip(outcome, err);
        Ok(())
    }

    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.sink.fragment_mismatch(member, volume)
    }

    /// The first member the look-ahead would take with nothing in flight:
    /// one a worker takes (`extract::offloadable`) that is not stored, or a
    /// small compressed one when those go ahead ([`Inner::goes_small`]),
    /// for a caller that is not selecting (`Inner::route`). A compressed
    /// member under the floor is told apart first, from the floor read once.
    #[inline(always)]
    fn hands_off(
        &self,
        solid_archive: bool,
        file: &crate::read::block::FileHdr,
        block: &crate::read::block::Block,
    ) -> bool {
        if self.selecting || matches!(file.method, Method::Stored) {
            return false;
        }
        let packed = block.data.end.saturating_sub(block.data.start);
        if file
            .unpacked_size
            .is_some_and(|n| n >= self.floor_compressed.max(1))
        {
            return extract::offloadable(
                solid_archive,
                file.solid,
                file.split_before,
                file.split_after,
                file.unpacked_size,
                packed,
                &file.method,
            );
        }
        self.small
            && extract::batchable(
                solid_archive,
                file.solid,
                file.split_before,
                file.split_after,
                file.unpacked_size,
                packed,
                &file.method,
            )
    }

    fn overlaps(&self) -> bool {
        true
    }

    fn closed(&mut self) -> Closed {
        std::mem::take(&mut self.closed)
    }
}
