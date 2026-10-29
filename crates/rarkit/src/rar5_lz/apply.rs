//! The decode ahead's offer and its apply, a wave's and a block's apply
//! to the window, and the probes that time the stages apart.

use super::*;

impl Rar5Lz {
    /// Offer a member that FOLLOWS the one about to be decoded to the
    /// chain's decode-ahead, answering whether it was taken.
    ///
    /// The offer is a hint and never a promise: `false` says the member
    /// decodes on the path it always did, which is what a full queue, a
    /// stated memory budget, a member too large and a member that does not
    /// start its own table group all answer. The bytes must be the
    /// member's WHOLE packed data, because the claim is on the content.
    // See `ahead::Ahead::offer`: the shipped read path offers from a
    // source through `offer_ahead_into`, and this form is the tests' and
    // the `internals_h2` seam's.
    #[cfg(feature = "parallel")]
    #[allow(dead_code)]
    pub(crate) fn offer_ahead(&mut self, packed: &[u8], unpacked: u64, algorithm: u8) -> bool {
        // THE SERIAL ARM IS SERIAL. `ParallelMode::Off` is what the
        // differential test of section 5.5, the fuzz target and the
        // `rar5_serial_vs_parallel` leg compare against, and a stage that
        // kept decoding ahead under it would leave them comparing the
        // parallel path with itself.
        if self.ahead_refused() {
            return false;
        }
        self.ahead.offer(packed, unpacked, algorithm)
    }

    /// The bytes [`Rar5Lz::ahead_refuses_head`] looks at: a RAR 5 block
    /// header is two bytes plus a size field of at most three (section 3.2).
    #[cfg(feature = "parallel")]
    pub(crate) const AHEAD_HEAD_PROBE: usize = block::HEAD_PROBE;

    /// Whether the chain's decode-ahead certainly refuses this member, asked
    /// BEFORE its packed bytes are read.
    ///
    /// `head` is the first [`Rar5Lz::AHEAD_HEAD_PROBE`] bytes of the
    /// member's packed data and the caller must hold that many: fewer is
    /// answered `false`, which costs the lever nothing and never refuses a
    /// member wrongly. `true` lets a caller skip the read entirely; see
    /// `ahead::Ahead::refused_by_head` for why it is one direction only.
    #[cfg(feature = "parallel")]
    pub(crate) fn ahead_refuses_head(&self, head: &[u8], unpacked: u64, len: usize) -> bool {
        if self.ahead_refused() {
            return true;
        }
        self.ahead.refused_by_head(head, unpacked, len)
    }

    /// Offer a member whose packed bytes are read STRAIGHT INTO the stage's
    /// buffer by `fill`, which is handed room for exactly `len` of them.
    ///
    /// The form a caller reading from a source uses. `fill` answering
    /// false, and every refusal [`Rar5Lz::offer_ahead`] can make, cost the
    /// stage nothing. The answer says whether a refusal is the member's
    /// for ever or the stage's for now (`ahead::Offered`), which is what
    /// the caller needs to know whether to step over the member or to
    /// stop on it.
    #[cfg(feature = "parallel")]
    pub(crate) fn offer_ahead_into<F>(
        &mut self,
        unpacked: u64,
        algorithm: u8,
        len: usize,
        fill: F,
    ) -> ahead::Offered
    where
        F: FnOnce(&mut [u8]) -> bool,
    {
        if self.ahead_refused() {
            return ahead::Offered::Never;
        }
        self.ahead.offer_into(unpacked, algorithm, len, fill)
    }

    /// The offering layer stepped over a member without offering it: the
    /// chain's decode-ahead closes its run, so the next member offered must
    /// open a table group of its own (see `ahead::Ahead::break_run`).
    #[cfg(feature = "parallel")]
    pub(crate) fn ahead_break(&mut self) {
        self.ahead.break_run();
    }

    /// Whether the chain's decode-ahead will take nothing more until
    /// something is claimed, which is what stops a caller walking ahead of
    /// the decode.
    #[cfg(feature = "parallel")]
    pub(crate) fn ahead_full(&self) -> bool {
        self.ahead_refused() || self.ahead.full()
    }

    /// Whether the chain's decode-ahead holds an offer not yet claimed.
    #[cfg(feature = "parallel")]
    pub(crate) fn ahead_in_flight(&self) -> bool {
        self.ahead.front().is_some()
    }

    /// Whether this stream refuses the chain's decode-ahead outright.
    ///
    /// THE SERIAL ARM IS SERIAL. `ParallelMode::Off` is what the
    /// differential test of section 5.5, the fuzz target and the
    /// `rar5_serial_vs_parallel` bench leg compare against, and a stage
    /// that kept decoding ahead under it would leave them comparing the
    /// parallel path with itself. The probe knob beside it is how the
    /// lever's own worth is read: the same extraction twice in one
    /// process, which is what survives a machine too loaded to time.
    #[cfg(feature = "parallel")]
    pub(super) fn ahead_refused(&self) -> bool {
        if matches!(self.parallel, ParallelMode::Off) {
            return true;
        }
        // A WIDTH OF ONE IS ONE CORE (SPEC-API 8.4.2): "At a
        // width of one (`-mt1`) NO decode lane runs beside the caller: the
        // one decode lane is the caller's own thread, which decodes,
        // applies and writes." The chain's decode-ahead lane is a decode
        // lane, and until 2 Oct 2026 it ran beside the caller at a width
        // of one, where on small members it also LOST: on a 20,000 member
        // chain written by reference `rar` at `-m3 -s`, `t -mt1` spent 1.7
        // cores and read 0.88x of 7zz on a 96 core Zen 5, and with no lane
        // the same chain decodes on the caller's thread in about half the
        // instructions (counted 2 Oct 2026). No
        // knob: it is the specification's sentence, not a lever.
        if self.width_one {
            return true;
        }
        #[cfg(feature = "test-support")]
        if crate::probe::ahead_off() {
            return true;
        }
        false
    }

    /// Apply a member the decode-ahead already decoded, in archive order.
    ///
    /// This is [`Rar5Lz::apply_one`] over a chain that was located and
    /// Huffman decoded on another thread, and it is the SAME function: a
    /// tape applied here cannot differ from one applied by the wave or the
    /// pipeline driver, because all three hand it to `tape::apply`.
    ///
    /// The three ends the chain can come to are the three
    /// [`Rar5Lz::member_planned`] has, in the same order and with the same
    /// errors: the member reached its declared size, the walk deferred a
    /// failure, or the chain ran out with no block flagged last.
    #[cfg(feature = "parallel")]
    pub(super) fn apply_ahead<P: PackedSource, S: LzSink>(
        &mut self,
        work: &mut ahead::Work,
        unpacked: u64,
        sink: &mut S,
        packed: &mut P,
    ) -> Result<()> {
        // A chain walk that could not start at all is the serial arm's
        // first-block error, raised before a byte is produced exactly as
        // `member_planned` raises it.
        if let Some(failure) = work.failure.take() {
            return Err(failure);
        }
        let mut used = 0usize;
        let mut done = false;
        for index in 0..work.blocks {
            let held = work.held[index].take();
            // The chain, its bytes and its tapes, borrowed apart so the
            // one tape being applied is mutable beside the plan that
            // located it.
            let (plan, bytes, tapes) = work.parts();
            let tape = &mut tapes[index];
            if self.apply_one(
                plan, bytes, tape, held, None, index, unpacked, sink, &mut used,
            )? {
                done = true;
                // WHERE THE SERIAL ARM WOULD HAVE STOPPED READING, which
                // is what `ahead::Ahead::give` checks the lane's carried
                // table set against (see that module's header).
                work.done_at = Some(index);
                break;
            }
        }
        packed.advance(used);
        if !done {
            // The chain ran out before its block flagged last. Deferred
            // until the apply stage genuinely reached it (section 3.8,
            // consequence 1); a member decodes every block it owns, so a
            // chain that ends early fails even where the declared size was
            // already produced (SPEC-H2 3.1), unless it ended on a header
            // that failed wholly past the declared end, which ends the
            // member's decode and passes it (3.1, as the serial walk).
            if let Some(failure) = work.plan.failure.take() {
                if self.window.produced() >= unpacked {
                    return Ok(());
                }
                return Err(failure);
            }
            // No block flagged last and no header left to fail: the
            // packed bytes ended at a block's edge. With the declared
            // size produced the member is whole, as the reference has it
            // (SPEC-H2 3.2) and as the serial walk answers; short of it,
            // the data was cut.
            if !work.plan.saw_last && self.window.produced() < unpacked {
                return Err(fault::truncated());
            }
        }
        Ok(())
    }

    /// Apply one decoded wave to the window, in archive order.
    ///
    /// Everything a decoded operation CONSUMES lives here and on this
    /// thread: the repeated distances, the last match length, the window,
    /// the filter queue and the sink. That is section 3.8's property read
    /// the other way round, and it is what lets the next wave be decoded
    /// while this one is applied. Answers whether the member finished.
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn apply_wave<S: LzSink>(
        &mut self,
        plan: &tape::Plan,
        packed: &[u8],
        wave: &mut tape::Wave,
        at: usize,
        unpacked: u64,
        sink: &mut S,
        used: &mut usize,
    ) -> Result<bool> {
        for (offset, (tape, held)) in wave.iter_mut().enumerate() {
            let held = held.take();
            if self.apply_one(
                plan,
                packed,
                tape,
                held,
                None,
                at + offset,
                unpacked,
                sink,
                used,
            )? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Apply ONE decoded tape to the window, in archive order, and answer
    /// whether the member finished: [`Rar5Lz::apply_tape`], with the one
    /// failure a tape's WALK can raise past the member's declared end
    /// answered as the block's end ([`Rar5Lz::walk_failed`]).
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub(super) fn apply_one<S: LzSink>(
        &mut self,
        plan: &tape::Plan,
        packed: &[u8],
        tape: &mut tape::BlockTape,
        held: Option<Arc<Tables>>,
        gather: Option<&symbols::Symbols>,
        index: usize,
        unpacked: u64,
        sink: &mut S,
        used: &mut usize,
    ) -> Result<bool> {
        match self.apply_tape(
            plan, packed, tape, held, gather, index, unpacked, sink, used,
        ) {
            Err(err) => self.walk_failed(err, plan, index, unpacked, used),
            done => done,
        }
    }

    /// A tape's apply ended in `err`. A SYMBOL that fails past the
    /// member's declared end ends its block and fails nothing (SPEC-H2
    /// 3.1, "A symbol that FAILS past the declared end"): the operations
    /// before it are applied, the rest of the tape, a parked remainder
    /// and a deferred failure included, are not, and the walk goes on
    /// with the member's next block. The lanes defer every failure they
    /// meet to [`Rar5Lz::surplus_tail`], which answers it so; the one that
    /// reaches here is a repeat of a distance never set, which only the
    /// apply walk can know, since the repeat state is this thread's.
    /// Anything else, and the same symbol before the declared end, is the
    /// member's failure as it was.
    ///
    /// Out of line and cold: it is reached only from a tape that failed.
    #[cfg(feature = "parallel")]
    #[cold]
    #[inline(never)]
    fn walk_failed(
        &mut self,
        err: crate::Error,
        plan: &tape::Plan,
        index: usize,
        unpacked: u64,
        used: &mut usize,
    ) -> Result<bool> {
        if self.window.produced() < unpacked || !ends_a_block(&err) {
            return Err(err);
        }
        *used = plan.blocks[index].past();
        plan.release_below(plan.group_of[index]);
        Ok(plan.blocks[index].ends_member())
    }

    /// Apply ONE decoded tape to the window, in archive order.
    ///
    /// Everything a decoded operation CONSUMES lives here and on this
    /// thread: the repeated distances, the last match length, the window,
    /// the filter queue and the sink. That is section 3.8's property read
    /// the other way round, and it is what lets later blocks be decoded
    /// while this one is applied. Answers whether the member finished.
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    fn apply_tape<S: LzSink>(
        &mut self,
        plan: &tape::Plan,
        packed: &[u8],
        tape: &mut tape::BlockTape,
        held: Option<Arc<Tables>>,
        gather: Option<&symbols::Symbols>,
        index: usize,
        unpacked: u64,
        sink: &mut S,
        used: &mut usize,
    ) -> Result<bool> {
        use crate::carry::c_lz::codec::rar50::TapeApplied;

        // THE STAGE PROBE. Everything above this line is the hand-off:
        // the lane decoded the block and this thread received it. Stopping
        // here times the plan, the lanes, the channel and the round robin
        // with the apply stage taken out, which is the subtraction this
        // lane exists to make. Compiled out without `h2-stage-probe`.
        #[cfg(feature = "h2-stage-probe")]
        if self.probe_no_apply {
            *used = plan.blocks[index].past();
            return Ok(false);
        }
        let handed = held.is_some();
        if let Some(tables) = held {
            self.current = Some(tables);
        }
        // THE SYMBOL PASS, where the block's lane made one and the live
        // window admits it; otherwise, and on every path that hands in no
        // symbols, the shipped walk exactly as before.
        let gathered = match gather {
            Some(gather) => symbols::apply(
                gather,
                &mut self.state,
                &mut self.window,
                &mut self.filters,
                unpacked,
                sink,
            )?,
            None => None,
        };
        // THE FAR LIST, where the lane wrote one whole and the list form
        // is on: a walk of its own, chosen here once a tape so that
        // `tape::apply` stays the control's walk for every tape without one.
        let applied = match gathered {
            Some(applied) => applied,
            // A tape whose repeats its lane resolved: a walk of its own,
            // chosen here once a tape as the far list's is. Taken, so the
            // tape cannot carry it into its next decode.
            None if tape.resolved.is_some() => {
                let end = tape.resolved.take().expect("tested just above");
                tape::apply_resolved(
                    tape,
                    end,
                    &mut self.state,
                    &mut self.window,
                    &mut self.filters,
                    unpacked,
                    sink,
                )?
            }
            // A stream the cache holds whole is never hinted
            // (`Window::FAR_DICTIONARY_FLOOR`); its lanes wrote no list.
            None => match tape::listed(tape).filter(|_| !self.window.far_off()) {
                Some(far) => tape::apply_listed(
                    tape,
                    far,
                    &mut self.state,
                    &mut self.window,
                    &mut self.filters,
                    unpacked,
                    sink,
                )?,
                None => tape::apply(
                    tape,
                    &mut self.state,
                    &mut self.window,
                    &mut self.filters,
                    unpacked,
                    sink,
                )?,
            },
        };
        *used = plan.blocks[index].past();
        // Every operation of the tape was applied, the member's surplus
        // past its declared size included (SPEC-H2 3.1): the tape walks
        // no longer stop at the declared size.
        debug_assert!(matches!(applied, TapeApplied::BlockDone));
        // A block the decode side PARKED is finished here, from the very
        // bit it stopped at, so the two paths cannot disagree.
        if let Some(bit) = tape.parked_at {
            let Some(tables) = self.current.clone() else {
                return Err(fault::empty_table());
            };
            let block = &plan.blocks[index];
            let mut bits = BitReader::new(block.payload(packed), block.bits());
            bits.seek(bit);
            // Preserve the ordinary decoder's original caller context.
            let decoded = if unpacked >= 65536
                && bits.remaining() >= 32768
                && serial_batch::admits(&tables)
            {
                serial_batch::dispatch(
                    &tables,
                    &mut self.state,
                    &mut self.window,
                    &mut self.filters,
                    &mut bits,
                    unpacked,
                    sink,
                )
            } else {
                decode_block(
                    &tables,
                    &mut self.state,
                    &mut self.window,
                    &mut self.filters,
                    &mut bits,
                    unpacked,
                    sink,
                )
            };
            self.surplus_tail(decoded, unpacked)?;
        } else if let Some(failure) = tape.failure.take() {
            // Deferred until the member genuinely reached it (section
            // 3.8, consequence 1), and answered as the serial loop answers
            // it past the declared end (`Rar5Lz::surplus_tail`).
            let failed = Err(failure);
            if self.tables_failed_past_end(
                plan.blocks[index].carries_tables(),
                handed,
                tape.steps.is_empty(),
                unpacked,
                &failed,
            ) {
                return Ok(true);
            }
            self.surplus_tail(failed, unpacked)?;
        }
        // Section 4.2: at most two table sets live at once. Every group
        // the apply stage has passed lets its set go, and the thread that
        // built it reuses the allocation (`tape::OwnTables`).
        plan.release_below(plan.group_of[index]);
        // DONE WHEN THE LAST BLOCK IS, not when the declared size is
        // produced: a member decodes every block it owns (SPEC-H2 3.1).
        Ok(plan.blocks[index].ends_member())
    }

    /// A block wholly PAST the declared end whose TABLES do not read (no
    /// set was handed over for it, or a table its first symbol needs was
    /// read empty) applied nothing: the member's decode ends there and it
    /// passes, and the set in force is DROPPED (SPEC-H2 3.1, the bullet of
    /// 28 Sep 2026), as the serial walk answers it. Answers whether that
    /// is what `failed` is, having dropped the set. Before this a table
    /// cut by its block's end passed in [`Rar5Lz::apply_one`] and the walk
    /// went on under the stale set, and any other failed the member.
    ///
    /// Out of line and cold on purpose: it is reached only from a tape's
    /// deferred failure, and written into `apply_one` it changed what the
    /// plain x86-64 build inlines on the lanes' path (4 Oct 2026, +1.4 to
    /// +1.9 percent instructions at the default width, 1.0000 with one
    /// codegen unit).
    #[cfg(feature = "parallel")]
    #[cold]
    #[inline(never)]
    fn tables_failed_past_end(
        &mut self,
        has_tables: bool,
        handed: bool,
        applied_nothing: bool,
        unpacked: u64,
        failed: &Result<()>,
    ) -> bool {
        let dropped = has_tables
            && applied_nothing
            && self.window.produced() >= unpacked
            && (!handed || member::empty_table(failed));
        if dropped {
            self.release_tables();
        }
        dropped
    }

    /// THE STAGE PROBE'S channel depth dial. See the field.
    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    pub(crate) fn set_probe_channel_depth(&mut self, depth: usize) {
        self.probe_channel_depth = depth.max(1);
    }

    /// THE STAGE PROBE: walk one member's chain and nothing else.
    ///
    /// Answers the blocks and the groups the walk found. The caller times
    /// the call, so `tape::plan` is priced with no decode and no apply
    /// behind it (SPEC-H2 section 7.3 item 4: the walk decodes no symbol).
    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    pub(crate) fn probe_plan_only(&mut self, packed: &[u8]) -> Result<(usize, usize)> {
        let mut plan = std::mem::take(&mut self.plan);
        let outcome = tape::plan(packed, self.current.is_some(), &mut plan);
        let shape = (plan.blocks.len(), plan.groups.len());
        self.plan = plan;
        outcome.map(|()| shape)
    }

    /// THE STAGE PROBE: the whole tape path with the APPLY STAGE REMOVED.
    ///
    /// The plan, the lanes, the channel of one, the round robin and the
    /// tape recycling all run exactly as they ship; the apply stage
    /// receives each tape and hands it straight back. So the wall this
    /// leaves is `D/W` plus every scheduling cost the plan carries, and
    /// subtracting it from the shipped wall is what says whether the plan
    /// or the apply stage is what a member's wall is made of.
    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    pub(crate) fn probe_decode_only(
        &mut self,
        packed: &[u8],
        unpacked: u64,
        algorithm: u8,
    ) -> Result<usize> {
        self.algorithm = algorithm;
        self.window.begin_member();
        self.window.set_output(unpacked);
        self.filters.begin(unpacked);
        self.probe_no_apply = true;
        let mut sink = crate::rar5_lz::output::NullSink { bytes: 0 };
        let mut plan = std::mem::take(&mut self.plan);
        // `tail` false: with no apply stage the member never reaches its
        // declared size, and the chain-exhausted checks would raise a
        // truncation this probe is not asking about.
        let outcome = self.member_planned(&mut plan, packed, unpacked, &mut sink, false);
        plan.clear();
        self.plan = plan;
        self.probe_no_apply = false;
        outcome.map(|(used, _)| used)
    }

    /// THE STAGE PROBE: the APPLY STAGE ALONE, with every tape already in
    /// hand and no lane, no channel and no plan walk left to pay for.
    ///
    /// Every block is decoded into its own tape first and none of that is
    /// timed: section 3.8's property is that a decode touches no window
    /// state, so holding the whole member's tapes changes not one applied
    /// byte. The closure is called once the tapes are ready and the clock
    /// starts inside it, so what it measures is the serial apply floor
    /// with the scheduling subtracted out completely.
    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    pub(crate) fn probe_apply_floor<S: LzSink>(
        &mut self,
        packed: &[u8],
        unpacked: u64,
        algorithm: u8,
        sink: &mut S,
    ) -> Result<std::time::Duration> {
        self.algorithm = algorithm;
        self.window.begin_member();
        self.window.set_output(unpacked);
        self.filters.begin(unpacked);
        let mut plan = std::mem::take(&mut self.plan);
        let outcome = self.probe_apply_floor_inner(&mut plan, packed, unpacked, sink);
        plan.clear();
        self.plan = plan;
        outcome
    }

    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    pub(super) fn probe_apply_floor_inner<S: LzSink>(
        &mut self,
        plan: &mut tape::Plan,
        packed: &[u8],
        unpacked: u64,
        sink: &mut S,
    ) -> Result<std::time::Duration> {
        tape::plan(packed, self.current.is_some(), plan)?;
        let carried = self.current.clone();
        // UNTIMED: the whole member decoded into tapes, one at a time on
        // this thread, so nothing below waits on a lane.
        let mut tapes: Vec<(tape::BlockTape, Option<Arc<Tables>>)> =
            Vec::with_capacity(plan.blocks.len());
        for index in 0..plan.blocks.len() {
            let mut tape = tape::BlockTape::default();
            let held = tape::decode_one_dispatch(
                plan,
                packed,
                self.algorithm,
                carried.as_ref(),
                index,
                &mut tape,
            );
            tapes.push((tape, held));
        }
        let mut used = 0usize;
        let start = std::time::Instant::now();
        for (index, (tape, held)) in tapes.iter_mut().enumerate() {
            let held = held.take();
            if self.apply_one(
                plan, packed, tape, held, None, index, unpacked, sink, &mut used,
            )? {
                break;
            }
        }
        self.window.drain(&mut *sink, &mut self.filters, true)?;
        Ok(start.elapsed())
    }

    /// THE LANE SPLIT PROBE:
    /// what ONE decode lane spends on a block, serially on this thread, split
    /// into the block's decode into a tape and the symbol pass's build over
    /// it. The tape is reused block to block as a lane reuses its tapes;
    /// the symbols are reused too (`mode` 0), or made new for every block
    /// (1), so the difference is what allocating and first touching a symbol
    /// buffer costs; `mode` 2 decodes and builds nothing, for a count by
    /// difference; `mode` 3 builds in the lean form, symbols reused. Nothing is applied and no window moves.
    #[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
    pub(crate) fn probe_lane_split(
        &mut self,
        packed: &[u8],
        algorithm: u8,
        mode: u8,
    ) -> Result<[u64; 18]> {
        self.algorithm = algorithm;
        let mut plan = std::mem::take(&mut self.plan);
        let outcome = (|| {
            tape::plan(packed, self.current.is_some(), &mut plan)?;
            let carried = self.current.clone();
            let mut tape = tape::BlockTape::default();
            let mut built = Box::<symbols::Symbols>::default();
            // blocks, ops, decode ns, build ns, blocks gathered, bytes
            // gathered, prefix ops, the largest symbol buffer in symbols,
            // then `symbols::probe_census`'s ten counts.
            let mut out = [0u64; 18];
            let mut shape = [0u64; 10];
            for index in 0..plan.blocks.len() {
                let from = std::time::Instant::now();
                let _ = tape::decode_one_dispatch(
                    &plan,
                    packed,
                    algorithm,
                    carried.as_ref(),
                    index,
                    &mut tape,
                );
                let decoded = std::time::Instant::now();
                if mode == 1 {
                    built = Box::default();
                }
                if mode == 3 {
                    built.build_lean(&tape, self.declared);
                } else if mode != 2 {
                    built.build(&tape, self.declared);
                }
                let done = std::time::Instant::now();
                let (ready, len, prefix_ops, capacity) = built.probe_shape();
                out[0] += 1;
                out[1] += tape.steps.len() as u64;
                out[2] += (decoded - from).as_nanos() as u64;
                out[3] += (done - decoded).as_nanos() as u64;
                out[4] += u64::from(ready);
                out[5] += if ready { len as u64 } else { 0 };
                out[6] += prefix_ops as u64;
                out[7] = out[7].max(capacity as u64);
                std::hint::black_box(&built);
                symbols::probe_census(&tape, &mut shape);
            }
            out[8..].copy_from_slice(&shape);
            Ok(out)
        })();
        plan.clear();
        self.plan = plan;
        outcome
    }
}
