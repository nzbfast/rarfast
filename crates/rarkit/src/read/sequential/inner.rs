//! The look-ahead's state: what is routed where, what has room, and delivery in order.

use super::*;

pub(super) enum State {
    /// `open` has given the walk this member's slot; nothing more yet. A
    /// member still here when the walk ends is the one it failed on.
    Opened,
    /// A worker is decoding it.
    Dispatched,
    /// The walk decoded it into its slot.
    Local { walk_bytes: u64 },
}

pub(super) struct Entry<W> {
    /// The caller's answer to `open`, when it was asked as the member was
    /// reached: a member reached with nothing ahead of it is next in
    /// archive order, so its `open` is asked THEN, and a `Skip` is known
    /// before anything is decoded.
    pub(super) pre: Option<Disposition<W>>,
    pub(super) slot: usize,
    pub(super) info: Owned,
    pub(super) reserved: u64,
    /// Whether those bytes are counted against the ceiling of a caller
    /// writing files in order (`Inner::under_ceiling`): not for a member
    /// the engine's own window holds.
    pub(super) ceilinged: bool,
    pub(super) state: State,
    /// No decoder claims the member (`Driver::note_refused`): a member the
    /// sink skips still counts as a failure and keeps its error, as on the
    /// sequential path (`Driver::skipped`).
    pub(super) refused: bool,
    /// The member's CRC32 runs here as its bytes are delivered.
    pub(super) crc_here: bool,
}

/// What the member between the walk's `open` and its `close` is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Current {
    None,
    Direct,
    Slot,
}

/// The sequential driver that decodes ahead: its state, shared between
/// [`Ahead`] and the [`Held`] observer through one cell.
pub(crate) struct Inner<'scope, 'env, 'k, K: Sink> {
    pub(super) sink: &'k mut K,
    pub(super) scope: &'scope Scope<'scope, 'env>,
    pub(super) policy: MemoryPolicy,
    pub(super) cancel: Option<Arc<AtomicBool>>,
    /// The read's width, the ceiling the lanes are spent against.
    pub(super) width: usize,
    /// Whether the caller STATED that width (`ReadOptions::workers`).
    pub(super) width_stated: bool,
    /// The members decoding at once: the workers.
    pub(super) breadth: usize,
    /// The members in the look-ahead at once.
    pub(super) outputs: usize,
    pub(super) budget: Option<Arc<crate::read::lanes::LaneBudget>>,
    pub(super) hands: Vec<Option<Hand>>,
    pub(super) free: Vec<usize>,
    pub(super) answers_tx: SyncSender<Answer>,
    pub(super) answers: Receiver<Answer>,
    pub(super) slots: Vec<Arc<Slot>>,
    pub(super) free_slots: Vec<usize>,
    pub(super) flight: VecDeque<Entry<K::Out>>,
    /// The declared bytes of every member in the look-ahead.
    pub(super) reserved: u64,
    pub(super) ceiling: u64,
    /// For a caller writing files in order (`ReadOptions::files_in_order`):
    /// the ceiling on the declared bytes of the members the engine's own
    /// window does NOT hold (`sequential::files_ceiling`), and what of
    /// `reserved` is theirs. Equal to `ceiling` for every other caller.
    pub(super) files_ceiling: u64,
    pub(super) under_ceiling: u64,
    pub(super) limit: u64,
    /// Under a NAMED budget (`extract::budget_floor`): the engine memory
    /// left for windows beside what the walk holds whatever the member,
    /// which the DECLARED charges are priced against in `room` and
    /// `dispatch`, while the operation's LIVE charges
    /// (`memory::op_current`) are priced against `limit`. `None` on the
    /// default path, where the declared charges alone meet `limit`.
    pub(super) window_room: Option<u64>,
    /// The reach of the RAR 5 ring the walk itself keeps, mirrored from
    /// the members it decoded at home by the rule its decoders apply
    /// (`Decoders::tight_reach_after`): what a member of its own adds to
    /// the operation's live figure is the ring after less the ring
    /// before, not the whole ring (`room_for_home`).
    pub(super) walk_reach: u64,
    pub(super) spares: Arc<Spares>,
    /// What the look-ahead holds decoded and not yet delivered, and the
    /// window its workers are held at ([`Gate`]).
    pub(super) gate: Arc<Gate>,
    /// The bytes of a chunk checksummed and written at a time as it is
    /// delivered; zero is the whole chunk.
    pub(super) piece: usize,
    /// A large member that barely packs, with little behind it in its
    /// volume, is decoded on the walking thread ([`goes_home`]).
    pub(super) homes_large: bool,
    /// One member's decode fills the machine at this read's width
    /// (`sequential::holds`): the gate holds, and large members that
    /// barely pack are taken one at a time.
    pub(super) narrow: bool,
    pub(super) reads: Arc<Reads>,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) current: Current,
    pub(super) solid_archive: bool,
    pub(super) closed: Closed,
    /// Decoded bytes delivered from workers, which the walk never counted.
    pub(super) delivered: u64,
    /// The operation has ended in an error: nothing more reaches the caller.
    pub(super) failed: bool,
    pub(super) spare_names: Vec<Vec<u8>>,
    /// The most the look-ahead ever reserved, for the report.
    pub(super) peak_reserved: u64,
    /// The caller has skipped a member that is not a directory: it is
    /// SELECTING, and from here nothing more is decoded ahead, so what a
    /// selecting caller pays for members it never wanted is bounded by
    /// the look-ahead it had at that moment.
    pub(super) selecting: bool,
    /// The member the walk is decoding was taken out of the look-ahead
    /// ([`Inner::here`]) and the caller skipped it.
    pub(super) skipped_here: bool,
    /// `extract::offload_floor_compressed`, read once for the operation
    /// rather than once a member ([`Inner::stays_home`]).
    pub(super) floor_compressed: u64,
    /// Compressed members under that floor go ahead onto the workers
    /// ([`SEQ_SMALL_ENV`], [`Inner::goes_small`]).
    pub(super) small: bool,
    /// The box a slot's writer rides in, when no member has it
    /// ([`SeqOut`]).
    pub(super) spare_out: Option<Box<Option<SlotOut>>>,
    /// The fragment mismatches of the member the walk is decoding into its
    /// slot, whose `open` the caller has not had yet: carried to its close
    /// in the slot's [`Finish`].
    pub(super) mismatches: Vec<u32>,
}

impl<'scope, 'env, 'k, K: Sink> Inner<'scope, 'env, 'k, K> {
    pub(super) fn new(
        scope: &'scope Scope<'scope, 'env>,
        sink: &'k mut K,
        opts: &crate::read::ReadOptions,
        room: Option<extract::Room>,
    ) -> Self {
        let width = opts.read_width().max(1);
        // A NAMED budget pays for so many workers beside the walk (the
        // pre-scan, `extract::budget_floor`).
        let breadth = look_ahead_breadth(width, workers_env())
            .min(room.map_or(usize::MAX, |room| room.workers))
            .max(1);
        // The look-ahead's workers get the room LESS the largest member's
        // need: a member above the ceiling is the walk's own, decoded at
        // home into the caller's writer in order, and its ring must fit
        // beside whatever the workers keep (8.3, one window per member in
        // flight, the walk's included). Reserved here rather than taken
        // at the member, because a worker's kept ring is given back only
        // when it takes a new member, and ordering it back was measured
        // to thrash (bin4g `p`).
        let limit = opts.memory.working_limit;
        // Under the whole-process default there is no pre-scan and so no
        // largest member to reserve for: the room is the limit itself, and
        // what it buys is the LIVE arm of the admission and the walk's own
        // ring making room before it (`MemoryPolicy::keeps_residency`).
        let window_room = room
            .map(|room| room.windows.saturating_sub(room.largest))
            .or_else(|| opts.memory.keeps_residency().then_some(limit));
        let outputs = breadth.saturating_mul(OUTPUTS_FACTOR).max(1);
        // A stated ceiling first (the measuring dial); else, for a caller
        // writing files in order, the ceiling counted for it; else the
        // limit alone.
        let ceiling = match ceiling_bytes() {
            0 => limit,
            n => n.min(limit),
        };
        let files_ceiling = match ceiling_bytes() {
            0 if opts.files_in_order => files_ceiling(limit),
            _ => ceiling,
        };
        let (answers_tx, answers) = sync_channel::<Answer>(breadth);
        // Idle buffers are counted by admission (`Inner::ahead`) and shed
        // before it waits, so the pool may keep up to the limit it answers
        // to rather than a fixed 256 MiB beside it.
        let spares = Arc::new(Spares::new(ceiling.min(limit)));
        let stop = Arc::new(AtomicBool::new(false));
        let narrow = holds(width);
        let window = if narrow { hold_bytes() } else { 0 };
        let budget = concurrent::shrinking().then(|| {
            Arc::new(
                crate::read::lanes::LaneBudget::with_spill(width, concurrent::spilling())
                    .abreast_on(crate::read::lanes::abreast_cores(opts.workers.is_some()))
                    // A stored member's lanes are granted in pieces of the
                    // window, not a gibibyte at a time: its worker is held
                    // at the gate with them.
                    .held_at(window),
            )
        });
        // The held workers wait where the budget's waiting members are
        // counted, so none is held while one waits (`lanes::Yield`).
        let place = budget.as_ref().map_or_else(Arc::default, |b| b.place());
        let gate = Arc::new(Gate::new(window, place));
        #[cfg(feature = "test-support")]
        crate::probe::watch_seq_ahead_gate(Some(Arc::clone(&gate)));
        Inner {
            sink,
            scope,
            policy: opts.memory,
            cancel: opts.cancel.clone(),
            width,
            width_stated: opts.workers.is_some(),
            breadth,
            outputs,
            budget,
            hands: (0..breadth).map(|_| None).collect(),
            free: (0..breadth).rev().collect(),
            answers_tx,
            answers,
            slots: Vec::with_capacity(outputs),
            free_slots: Vec::with_capacity(outputs),
            flight: VecDeque::with_capacity(outputs),
            reserved: 0,
            ceiling,
            files_ceiling,
            under_ceiling: 0,
            limit,
            window_room,
            walk_reach: 0,
            spares,
            gate,
            piece: deliver_piece(),
            homes_large: homes_large(),
            narrow,
            reads: Arc::new(Reads::default()),
            stop,
            current: Current::None,
            solid_archive: false,
            closed: Closed::default(),
            delivered: 0,
            failed: false,
            spare_names: Vec::with_capacity(outputs + breadth),
            peak_reserved: 0,
            selecting: false,
            skipped_here: false,
            mismatches: Vec::new(),
            floor_compressed: extract::offload_floor_compressed(),
            small: small_engaged(),
            spare_out: None,
        }
    }

    /// The tape lanes a dispatched member may open: the budget decides
    /// where there is one, as in the parallel pool.
    pub(super) fn inner_width(&self) -> usize {
        if self.budget.is_some() {
            return self.width;
        }
        (self.width / self.breadth.max(1)).max(1)
    }

    /// What the look-ahead's own bytes hold: the larger of the members'
    /// DECLARED sizes and the capacity of the chunk buffers out for them,
    /// plus the idle pool. Declared sizes alone read a small member handed
    /// a warm 1 MiB buffer as its few KiB, and the idle pool as nothing.
    pub(super) fn ahead(&self) -> u64 {
        let (idle, out) = self.spares.resident();
        self.reserved.max(out).saturating_add(idle)
    }

    pub(super) fn committed(&self) -> u64 {
        self.hands
            .iter()
            .flatten()
            .fold(0u64, |sum, h| sum.saturating_add(h.held))
    }

    pub(super) fn name_buf(&mut self) -> Vec<u8> {
        self.spare_names.pop().unwrap_or_default()
    }

    pub(super) fn recycle_name(&mut self, name: Vec<u8>) {
        if self.spare_names.len() < self.spare_names.capacity() {
            self.spare_names.push(name);
        }
    }

    pub(super) fn answered(&mut self, answer: Answer) {
        let Answer {
            worker,
            working,
            name,
        } = answer;
        if let Some(hand) = self.hands[worker].as_mut() {
            hand.working = working;
            hand.held = hand.held.max(working);
        }
        self.free.push(worker);
        self.recycle_name(name);
    }

    /// Take every worker's answer that has arrived, without waiting.
    ///
    /// Nothing to take while every worker is free: a worker answers only
    /// a task, and a worker with a task is not in `free`. Asked first so a
    /// member that runs on the walking thread, with nothing dispatched,
    /// does not poll the channel for an answer that cannot be there.
    pub(super) fn harvest(&mut self) {
        if self.free.len() == self.breadth {
            return;
        }
        while let Ok(answer) = self.answers.try_recv() {
            self.answered(answer);
        }
    }

    /// Whether the front of the look-ahead can be delivered now: it is not
    /// the member the walk is in the middle of.
    pub(super) fn front_ready(&self) -> bool {
        self.flight
            .front()
            .is_some_and(|e| !matches!(e.state, State::Opened))
    }

    /// Where a member the walk has reached goes.
    pub(super) fn route(&self, info: &MemberInfo<'_>) -> Option<u64> {
        if self.selecting || self.solid_archive || info.split_before || info.split_after {
            return None;
        }
        let size = info.unpacked_size?;
        if size > self.most_for(size, info.packed_size) {
            return None;
        }
        let takes_a_worker = extract::offloadable(
            self.solid_archive,
            info.solid,
            info.split_before,
            info.split_after,
            info.unpacked_size,
            info.packed_size,
            &info.method,
        );
        if takes_a_worker {
            if matches!(info.method, Method::Stored) && self.flight.is_empty() {
                return None;
            }
            return Some(size);
        }
        if self.goes_small(info) {
            return Some(size);
        }
        (!self.flight.is_empty() && size <= LOCAL_MAX).then_some(size)
    }

    /// Whether a member of `size` declared bytes in `packed` is bounded by
    /// the ceiling of a caller writing files in order, and not by the
    /// engine's own window ([`bounded_by_ceiling`]).
    pub(super) fn ceilinged(&self, size: u64, packed: u64) -> bool {
        bounded_by_ceiling(self.narrow, size, packed)
    }

    /// The most declared bytes that may be ahead when such a member is
    /// admitted: its own ceiling, or the look-ahead's whole one.
    pub(super) fn most_for(&self, size: u64, packed: u64) -> u64 {
        if self.ceilinged(size, packed) {
            self.files_ceiling
        } else {
            self.ceiling
        }
    }

    /// Room in the look-ahead for a member declaring `need` bytes: the
    /// front is delivered until there is. `ceilinged` members also wait
    /// for the bytes of their own kind to fit their ceiling.
    pub(super) fn room(&mut self, need: u64, ceilinged: bool) -> Result<()> {
        loop {
            // Idle chunk buffers go before anything waits for them.
            let (_, out) = self.spares.resident();
            let busy = self
                .committed()
                .saturating_add(self.reserved.max(out))
                .saturating_add(need);
            self.spares.shed(self.limit.saturating_sub(busy));
            let declared = self.committed().saturating_add(self.ahead());
            let full = self.flight.len() >= self.outputs
                || self.reserved.saturating_add(need) > self.ceiling
                || (ceilinged && self.under_ceiling.saturating_add(need) > self.files_ceiling)
                || self.over(declared, need);
            if !full {
                return Ok(());
            }
            if self.front_ready() {
                self.deliver_front()?;
                continue;
            }
            // Over the limit with nothing to deliver yet: a worker's answer
            // is what makes the front deliverable and frees what its member
            // holds, so wait for one rather than admit past the limit
            // (API 8.4.1: the ceiling is hard). Only with no worker busy is
            // there nothing to wait for.
            if !self.await_answer()? {
                return Ok(());
            }
        }
    }

    /// Whether `need` more bytes on top of `declared` (the windows the
    /// workers have committed and the look-ahead's own chunks) would pass
    /// the ceiling. Under a NAMED budget the declared sum must fit the
    /// room the walk's own holdings leave, and the operation's LIVE
    /// charges (`memory::op_current`: every ring, the walk's and the
    /// seam's included, every scratch and every chunk) plus `need` must
    /// fit the limit itself, which is the figure the ceiling is measured
    /// on (8.4.1). On the default path the declared sum meets the limit,
    /// as before.
    pub(super) fn over(&self, declared: u64, need: u64) -> bool {
        self.over_with(declared, 0, need)
    }

    /// As [`Inner::over`], for a worker already holding `mine` of the
    /// declared and live figures, taking a member charged `charge`.
    pub(super) fn over_with(&self, declared: u64, mine: u64, charge: u64) -> bool {
        let after = declared.saturating_add(charge);
        match self.window_room {
            Some(room) => {
                let live = crate::memory::op_current();
                let after_live = live.saturating_sub(mine).saturating_add(charge);
                after > room || after_live > self.limit
            }
            None => after > self.limit,
        }
    }

    /// Under a NAMED budget, before the walk decodes `member` itself:
    /// while the window the member reaches, on top of what the operation
    /// holds live, would pass the limit, the members still decoding ahead
    /// are waited for and delivered (the home member's bytes follow theirs
    /// in any case), and then the idle chunk buffers are shed down to what
    /// leaves the member its room. Without this the walk built a 32 MiB
    /// ring beside 22 MiB of idle chunks and the workers' rings, 8 MiB
    /// over its limit on bin4g `p` at -mm128m (counted).
    pub(super) fn room_for_home(&mut self, member: &MemberInfo<'_>) -> Result<()> {
        if self.window_room.is_none() {
            return Ok(());
        }
        let Method::Compressed { dictionary, .. } = member.method else {
            return Ok(());
        };
        let reach = if self.solid_archive {
            dictionary
        } else {
            member
                .unpacked_size
                .map_or(dictionary, |n| n.min(dictionary))
        };
        self.room_for_ring(dictionary, reach)
    }

    /// [`Inner::room_for_home`] for a member the look-ahead hands back to
    /// the walk from its own slot ([`Inner::here`]), priced from the job's
    /// codec.
    pub(super) fn room_for_job(&mut self, job: &Job<SeqOut<K::Out>>) -> Result<()> {
        if self.window_room.is_none() {
            return Ok(());
        }
        if let extract::Codec::Rar5 { window, reach, .. } = job.codec {
            return self.room_for_ring(window, reach);
        }
        Ok(())
    }

    /// The room for the walk's own RAR 5 ring for a member of `reach`
    /// under `dictionary` (`room_for_home`).
    pub(super) fn room_for_ring(&mut self, dictionary: u64, reach: u64) -> Result<()> {
        // What the walk's ring will add: the ring after this member less
        // the one it keeps now, by its decoders' own rule.
        let after = extract::Decoders::tight_reach_after(
            self.walk_reach,
            dictionary,
            reach,
            self.solid_archive,
            &self.policy,
        );
        let ceiling = self.policy.max_window;
        let need = extract::Decoders::ring_bytes(after, ceiling)
            .saturating_sub(extract::Decoders::ring_bytes(self.walk_reach, ceiling));
        self.walk_reach = after;
        if need == 0 {
            return Ok(());
        }
        loop {
            self.drain()?;
            let declared = self.committed().saturating_add(self.ahead());
            if !self.over(declared, need) {
                return Ok(());
            }
            if !self.await_answer()? {
                break;
            }
        }
        // Everything ahead is delivered; what is left live beside the idle
        // chunks is the workers' kept rings and the walk's own, and the
        // chunks go down to what fits beside them.
        let (idle, _) = self.spares.resident();
        let others = crate::memory::op_current().saturating_sub(idle);
        self.spares
            .shed(self.limit.saturating_sub(others.saturating_add(need)));
        Ok(())
    }

    /// Wait for one busy worker's answer. `false` when no worker is busy,
    /// so nothing in flight can free room.
    pub(super) fn await_answer(&mut self) -> Result<bool> {
        self.harvest();
        if self.free.len() >= self.breadth {
            return Ok(false);
        }
        match self.recv_answer() {
            Some(a) => {
                self.answered(a);
                Ok(true)
            }
            None => Err(Error::new(ErrorKind::Corrupt(
                crate::error::Corruption::Stream,
            ))),
        }
    }

    /// Block for a worker's answer, with the gate lifted for the wait:
    /// this thread delivers nothing while it is here, so a worker held at
    /// the gate would be waiting for it ([`Gate`]).
    pub(super) fn recv_answer(&mut self) -> Option<Answer> {
        self.gate.lift(true);
        let answer = self.answers.recv().ok();
        self.gate.lift(false);
        answer
    }

    /// Hand every member in the look-ahead to the caller.
    pub(super) fn drain(&mut self) -> Result<()> {
        while self.front_ready() {
            self.deliver_front()?;
        }
        Ok(())
    }

    /// A free worker, waiting for one if every one is decoding.
    pub(super) fn free_worker(&mut self) -> Result<usize> {
        loop {
            self.harvest();
            if let Some(worker) = self.free.pop() {
                return Ok(worker);
            }
            let mut sweep = super::super::spin::Spin::new(concurrent::settle_spin_us());
            let mut got = None;
            while !sweep.parks_at_once() {
                match self.answers.try_recv() {
                    Ok(a) => {
                        got = Some(a);
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        if sweep.over() {
                            break;
                        }
                        std::hint::spin_loop();
                    }
                    Err(TryRecvError::Disconnected) => break,
                }
            }
            if let Some(a) = got {
                self.answered(a);
                continue;
            }
            if self.front_ready() {
                self.deliver_front()?;
                continue;
            }
            // Every worker is decoding a member ahead of the front, which
            // is the walk's own: wait for any of them.
            match self.recv_answer() {
                Some(a) => self.answered(a),
                None => {
                    return Err(Error::new(ErrorKind::Corrupt(
                        crate::error::Corruption::Stream,
                    )))
                }
            }
        }
    }

    pub(super) fn fail(&mut self) {
        self.failed = true;
        self.stop.store(true, Ordering::Relaxed);
        self.gate.open();
    }

    /// [`Slot::abandon`] for a slot of the look-ahead: what it drops
    /// leaves the gate's count, and a worker held on it goes on to find it
    /// abandoned.
    pub(super) fn abandon(&self, cell: &Slot) {
        let dropped = cell.abandon(&self.spares);
        self.gate.dropped(dropped);
    }

    /// Hand the member at the front of the look-ahead to the caller: its
    /// `open`, its bytes as they arrive, its `close`.
    pub(super) fn deliver_front(&mut self) -> Result<()> {
        let Some(entry) = self.flight.pop_front() else {
            return Ok(());
        };
        let Entry {
            pre,
            slot,
            info,
            reserved,
            ceilinged,
            state,
            refused: entry_refused,
            crc_here,
        } = entry;
        self.reserved = self.reserved.saturating_sub(reserved);
        if ceilinged {
            self.under_ceiling = self.under_ceiling.saturating_sub(reserved);
        }
        let cell = Arc::clone(&self.slots[slot]);
        let outcome = self.deliver(pre, &cell, &info, &state, entry_refused, crc_here);
        if outcome.is_err() {
            self.fail();
            self.abandon(&cell);
            // The slot is not reused: its producer may still be finishing.
        } else {
            cell.reset();
            self.free_slots.push(slot);
        }
        self.recycle_name(info.name);
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn deliver(
        &mut self,
        pre: Option<Disposition<K::Out>>,
        cell: &Slot,
        info: &Owned,
        state: &State,
        refused: bool,
        crc_here: bool,
    ) -> Result<()> {
        let view = info.view();
        let disposition = match pre {
            Some(d) => d,
            None => self.sink.open(&view)?,
        };
        let (mut writer, skip) = match disposition {
            Disposition::Write(w) => (Some(w), false),
            Disposition::Verify => (None, false),
            Disposition::Skip => (None, true),
        };
        if skip {
            // Nobody reads the rest: stop its producer at its next chunk.
            self.abandon(cell);
            self.selecting |= !view.is_directory;
        }
        let spin = concurrent::settle_spin_us();
        let mut crc = (crc_here && !skip).then(Crc32::new);
        let finish = loop {
            match cell.next(spin) {
                Next::Chunk(buf) => {
                    let data = &buf[..];
                    self.gate.took(data.len() as u64, cell);
                    // Where the checksum runs here, it and the write take
                    // the chunk a PIECE at a time, so the write's copy
                    // reads bytes the fold has just left in this core's
                    // cache (`PIECE_DEFAULT`). With no fold here the chunk
                    // is written whole, as before.
                    let piece = match self.piece {
                        n if n > 0 && crc.is_some() => n,
                        _ => data.len().max(1),
                    };
                    let mut failed = None;
                    for part in data.chunks(piece) {
                        if let Some(c) = crc.as_mut() {
                            c.update(part);
                        }
                        if let Some(w) = writer.as_mut() {
                            if let Err(e) = w.write_all(part) {
                                failed = Some(e);
                                break;
                            }
                        }
                    }
                    if let Some(e) = failed {
                        self.spares.put(buf);
                        return Err(Error::from(e));
                    }
                    if writer.is_some()
                        && self
                            .cancel
                            .as_deref()
                            .is_some_and(|c| c.load(Ordering::Relaxed))
                    {
                        self.spares.put(buf);
                        return Err(Error::new(ErrorKind::Cancelled));
                    }
                    self.spares.put(buf);
                }
                // The look-ahead's producers make no notes: its walk runs
                // on this thread and calls `Progress` itself.
                Next::Note(_) => {}
                // Nor ranges: a worker's writer here is a slot, which
                // takes bytes and nothing else.
                Next::Range(_) => {}
                Next::Done(f) => break f,
            }
        };
        if skip {
            // Never decoded on the sequential path, so never counted, and
            // its decode's failure is nobody's. It is counted as the
            // sequential path counts a member it skipped, and the caller
            // hears nothing more of it, its fragments included
            // (`Driver::skipped`); one no decoder claims fails, there as here.
            if let State::Local { walk_bytes } = state {
                self.closed.walk_bytes_skipped += walk_bytes;
            }
            let outcome = MemberOutcome {
                checksum_ok: refused.then_some(false),
                bytes: 0,
                password_refused: false,
                fragment_mismatches: 0,
            };
            self.closed.skip(&outcome, finish.error.filter(|_| refused));
            return Ok(());
        }
        let Finish {
            bytes,
            verdict,
            checksum_ok,
            error,
            fatal,
            writer: gives_writer,
            mismatches,
        } = finish;
        let checksum_ok = match (verdict, crc) {
            (Some(v), Some(c)) => v.finish(c),
            _ => checksum_ok,
        };
        if fatal {
            return Err(error.unwrap_or_else(|| Error::new(ErrorKind::Cancelled)));
        }
        if matches!(state, State::Dispatched) {
            self.delivered += bytes;
            self.closed.bytes += bytes;
        }
        self.closed.members += 1;
        if checksum_ok == Some(false) {
            self.closed.checksum_failures += 1;
        }
        let out = if gives_writer { writer } else { None };
        for &volume in &mismatches {
            self.sink.fragment_mismatch(&view, volume)?;
        }
        let result = self.sink.close(
            &view,
            out,
            &MemberOutcome {
                checksum_ok,
                bytes,
                password_refused: crate::read::password_refused(error.as_ref()),
                fragment_mismatches: u32::try_from(mismatches.len()).unwrap_or(u32::MAX),
            },
        );
        if self.closed.deferred.is_none() {
            self.closed.deferred = error;
        }
        result
    }

    /// Start worker `at`'s thread if this is its first job. `false` when
    /// the host will not start it (`crate::threads`): the slot is retired
    /// for the rest of the read, which runs at the breadth it has.
    pub(super) fn start(&mut self, at: usize) -> bool {
        if self.hands[at].is_some() {
            return true;
        }
        self.hands[at] = spawn(
            self.scope,
            at,
            self.policy,
            self.cancel.clone(),
            self.budget.clone(),
            Arc::clone(&self.reads),
            self.answers_tx.clone(),
            self.width_stated,
        );
        if self.hands[at].is_none() {
            // Never put back on the free list, so every count of idle
            // workers against the breadth still reads true.
            self.breadth -= 1;
            return false;
        }
        true
    }

    /// The member the walk offered, decoded by the walk itself because no
    /// worker could take it: every member ahead of it is delivered first,
    /// which is what makes this its turn for [`Inner::here`].
    pub(super) fn home_in_turn(
        &mut self,
        job: Job<SeqOut<K::Out>>,
    ) -> Result<Option<Job<SeqOut<K::Out>>>> {
        while self.flight.len() > 1 && self.front_ready() {
            self.deliver_front()?;
        }
        self.room_for_job(&job)?;
        self.here(job).map(Some)
    }

    /// Take the member the walk offered back out of the look-ahead and
    /// give the walk the caller's own output for it, `open` called now:
    /// nothing is ahead of it, so this IS its turn in archive order.
    pub(super) fn here(&mut self, mut job: Job<SeqOut<K::Out>>) -> Result<Job<SeqOut<K::Out>>> {
        let entry = self
            .flight
            .pop_back()
            .expect("the member offered is in the look-ahead");
        self.reserved = self.reserved.saturating_sub(entry.reserved);
        if entry.ceilinged {
            self.under_ceiling = self.under_ceiling.saturating_sub(entry.reserved);
        }
        self.slots[entry.slot].reset();
        self.free_slots.push(entry.slot);
        if let Out::Write(SeqOut::Ahead(mut boxed)) = std::mem::replace(&mut job.out, Out::Verify) {
            if let Some(mut o) = boxed.take() {
                self.spares.put(std::mem::take(&mut o.cur));
            }
            self.spare_out = Some(boxed);
        }
        self.current = Current::Direct;
        let Entry { pre, info, .. } = entry;
        let disposition = match pre {
            Some(d) => Ok(d),
            None => self.sink.open(&info.view()),
        };
        self.recycle_name(info.name);
        job.out = match disposition? {
            Disposition::Write(w) => Out::Write(SeqOut::Direct(w)),
            Disposition::Verify => Out::Verify,
            Disposition::Skip => {
                // The walk still decodes it (the job is already built),
                // and its `close` is the one the sequential path gives a
                // skipped member.
                self.skipped_here = true;
                self.selecting = true;
                Out::Verify
            }
        };
        Ok(job)
    }

    /// `open` for a member the idle path did not settle: the look-ahead's
    /// own routing, out of line so the idle path stays small.
    #[inline(never)]
    pub(super) fn open_routed(
        &mut self,
        member: &MemberInfo<'_>,
    ) -> Result<Disposition<SeqOut<K::Out>>> {
        self.harvest();
        match self.route(member) {
            Some(need) => {
                let ceilinged = self.ceilinged(need, member.packed_size);
                self.room(need, ceilinged)?;
                let pre = if self.flight.is_empty() {
                    match self.sink.open(member)? {
                        Disposition::Skip => {
                            self.selecting |= !member.is_directory;
                            self.current = Current::Direct;
                            return Ok(Disposition::Skip);
                        }
                        d => Some(d),
                    }
                } else {
                    None
                };
                let slot = self.slot();
                let name = self.name_buf();
                self.flight.push_back(Entry {
                    pre,
                    slot,
                    info: Owned::of(member, name),
                    reserved: need,
                    ceilinged,
                    state: State::Opened,
                    refused: false,
                    crc_here: false,
                });
                self.reserved += need;
                if ceilinged {
                    self.under_ceiling += need;
                }
                self.peak_reserved = self.peak_reserved.max(self.reserved);
                #[cfg(feature = "test-support")]
                crate::probe::note_seq_ahead(self.flight.len(), self.reserved);
                self.current = Current::Slot;
                let out = self.slot_out(slot, need);
                Ok(Disposition::Write(SeqOut::Ahead(self.lend(out))))
            }
            None => {
                self.drain()?;
                self.room_for_home(member)?;
                self.open_here(member)
            }
        }
    }

    /// `close` for the member the walk decoded into its slot.
    #[inline(never)]
    pub(super) fn close_slot(
        &mut self,
        out: Option<SeqOut<K::Out>>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        let entry = self
            .flight
            .back_mut()
            .expect("a member given a slot is in the look-ahead");
        entry.state = State::Local {
            walk_bytes: outcome.bytes,
        };
        let finish = Finish {
            bytes: outcome.bytes,
            verdict: None,
            checksum_ok: outcome.checksum_ok,
            error: err,
            fatal: false,
            writer: out.is_some(),
            mismatches: std::mem::take(&mut self.mismatches),
        };
        match out {
            Some(SeqOut::Ahead(mut boxed)) => {
                match boxed.take() {
                    Some(o) => o.seal(finish),
                    None => self.slots[entry.slot].finish(finish),
                }
                self.spare_out = Some(boxed);
            }
            _ => self.slots[entry.slot].finish(finish),
        }
        Ok(())
    }

    /// `close` for a member that ran into the caller's own writer.
    #[inline(always)]
    pub(super) fn close_here(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<SeqOut<K::Out>>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.closed.members += 1;
        if std::mem::take(&mut self.skipped_here) {
            // Taken out of the look-ahead and then skipped by the caller:
            // decoded, but counted as a skipped member is, and not closed
            // (`Driver::skipped`).
            self.closed.walk_bytes_skipped += outcome.bytes;
            return Ok(());
        }
        if outcome.checksum_ok == Some(false) {
            self.closed.checksum_failures += 1;
        }
        let out = match out {
            Some(SeqOut::Direct(w)) => Some(w),
            _ => None,
        };
        self.sink.close(member, out, outcome)?;
        if self.closed.deferred.is_none() {
            self.closed.deferred = err;
        }
        Ok(())
    }

    /// A member that cannot go ahead while the look-ahead is empty,
    /// answered from the member alone: `route` gives such a member a slot
    /// only when a worker takes it (`extract::offloadable`) and it is not
    /// stored, and a compressed member under the floor takes no worker
    /// unless the small members go ahead ([`Inner::goes_small`]).
    #[inline(always)]
    pub(super) fn stays_home(&self, member: &MemberInfo<'_>) -> bool {
        (matches!(member.method, Method::Stored)
            || member
                .unpacked_size
                .is_none_or(|n| n < self.floor_compressed.max(1)))
            && !self.goes_small(member)
    }

    /// Whether a compressed member under the offload floor goes ahead onto
    /// a worker, one member a task, rather than being decoded by the walk
    /// ([`SEQ_SMALL_ENV`]). An archive of such members otherwise decodes
    /// on the walking thread alone, one core, where `extract_parallel`
    /// pools the same members in its small batches: `p` of 20,000 members
    /// of 3.7 KiB, 0.232 s against `t`'s 0.075 s
    /// (measured 30 Sep 2026). The member's
    /// slot bounds it as any member's does, and it is delivered in order
    /// as any member is.
    #[inline(always)]
    pub(super) fn goes_small(&self, member: &MemberInfo<'_>) -> bool {
        self.small
            && !self.selecting
            && extract::batchable(
                self.solid_archive,
                member.solid,
                member.split_before,
                member.split_after,
                member.unpacked_size,
                member.packed_size,
                &member.method,
            )
    }

    /// The sequential path's `open`, for a member that runs on the
    /// walking thread into the caller's own writer.
    #[inline(always)]
    pub(super) fn open_here(
        &mut self,
        member: &MemberInfo<'_>,
    ) -> Result<Disposition<SeqOut<K::Out>>> {
        self.current = Current::Direct;
        Ok(match self.sink.open(member)? {
            Disposition::Write(w) => Disposition::Write(SeqOut::Direct(w)),
            Disposition::Verify => Disposition::Verify,
            Disposition::Skip => {
                self.selecting |= !member.is_directory;
                Disposition::Skip
            }
        })
    }

    pub(super) fn slot(&mut self) -> usize {
        if let Some(at) = self.free_slots.pop() {
            return at;
        }
        self.slots.push(Arc::new(Slot::default()));
        self.slots.len() - 1
    }

    /// The one box, lent with `out` in it ([`SeqOut`]).
    pub(super) fn lend(&mut self, out: SlotOut) -> Box<Option<SlotOut>> {
        match self.spare_out.take() {
            Some(mut boxed) => {
                *boxed = Some(out);
                boxed
            }
            None => Box::new(Some(out)),
        }
    }

    pub(super) fn slot_out(&self, slot: usize, declared: u64) -> SlotOut {
        SlotOut {
            slot: Arc::clone(&self.slots[slot]),
            spares: Arc::clone(&self.spares),
            cur: self.spares.take(declared.min(CHUNK as u64) as usize),
            left: declared,
            stop: Arc::clone(&self.stop),
            gate: Arc::clone(&self.gate),
            waits: false,
        }
    }
}

impl<K: Sink> Drop for Inner<'_, '_, '_, K> {
    /// However the operation ends, no worker is left held at the gate: the
    /// scope that owns them joins them after this.
    fn drop(&mut self) {
        #[cfg(feature = "test-support")]
        crate::probe::watch_seq_ahead_gate(None);
        self.gate.open();
    }
}
