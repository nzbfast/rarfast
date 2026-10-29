//! A member's walks: the one entry and the forms it takes, block at a
//! time, by waves on the pool, streamed, planned, on one thread and
//! piped, and the member's end.

use super::*;

/// Whether a block's decode ended on `EmptyTable`: with nothing applied,
/// a table the block's first symbol needs was read with no code in it.
pub(super) fn empty_table(decoded: &Result<()>) -> bool {
    matches!(decoded, Err(err) if matches!(
        err.kind(),
        crate::ErrorKind::Corrupt(crate::Corruption::Rar5(crate::Rar5Fault::EmptyTable))
    ))
}

/// A member's outcome when a kept filter span was still waiting at its
/// end: the stream never completed the span. Where the member's blocks
/// ended validly and left it short, the bytes it is short of are the
/// ones that span held back, and that is `FilterRange` and not
/// `IncompleteMember` (SPEC-H2 3.6, "A span the member's stream does not
/// complete, starting inside the declared output", and 3.1, "a member
/// never ends short at a filter boundary"). The name matters to the
/// reader: an `IncompleteMember` is judged by the member's checksum
/// (spec F 4.2), and a checksum of the bytes before the span must not
/// pass a member whose span never ran. Any other outcome stands.
#[cold]
#[inline(never)]
fn kept_short(outcome: Result<()>) -> Result<()> {
    match outcome {
        Err(err)
            if matches!(
                err.kind(),
                crate::ErrorKind::Corrupt(crate::Corruption::Rar5(
                    crate::Rar5Fault::IncompleteMember
                ))
            ) =>
        {
            Err(fault::filter_range())
        }
        other => other,
    }
}

impl Rar5Lz {
    /// Decode one member's packed bytes into `sink`.
    ///
    /// A kept filter span that leaves the member's declared output fails
    /// the member `FilterRange` (SPEC-H2 3.6) and is reported FIRST, ahead
    /// of anything later in the member, but only once the member's blocks
    /// are decoded: the symbols after the record still move the window the
    /// next member of a solid stream counts from (3.1, 28 Sep 2026).
    pub(crate) fn member<P: PackedSource, S: LzSink>(
        &mut self,
        packed: &mut P,
        unpacked_size: u64,
        algorithm: u8,
        sink: &mut S,
    ) -> Result<()> {
        let checked = !std::mem::take(&mut self.unchecked);
        if !checked {
            self.filters.carries_no_checksum();
        }
        let outcome = self.member_blocks(packed, unpacked_size, algorithm, sink);
        let open = self.filters.span_open();
        match self.filters.take_failed(self.window.produced(), checked) {
            Some(failure) => Err(failure),
            None if open => kept_short(outcome),
            None => outcome,
        }
    }

    /// [`Rar5Lz::member`] less its deferred filter failure.
    pub(super) fn member_blocks<P: PackedSource, S: LzSink>(
        &mut self,
        packed: &mut P,
        unpacked_size: u64,
        algorithm: u8,
        sink: &mut S,
    ) -> Result<()> {
        self.algorithm = algorithm;
        self.window.begin_member();
        self.window.set_output(unpacked_size);
        self.filters.begin(unpacked_size);
        self.continuing = self.chain_members > 0;
        self.chain_members = self.chain_members.saturating_add(1);

        // A MEMBER THAT DECLARES NO BYTES STILL CARRIES ITS BLOCKS' TABLES,
        // and takes its own path: it reads its blocks' tables and decodes
        // every symbol they carry, with no output, as any member does past
        // its declared end (SPEC-H2 3.1, reconciled 28 Sep 2026); the
        // blocks genuine rar writes on an empty member carry tables and no
        // symbol. A block that does not read drops
        // the set rather than failing a member that owes no bytes, and a
        // member with no packed bytes at all owns no block (the loop below
        // would call it truncated). Reference `rar` 7.23 at
        // `-m3 -s` writes zero byte members in the middle of
        // a solid chain with a packed block of their own that carries a
        // table set, and the member after such a one, its first block's
        // table bit clear, decodes under THAT set (section 3.2: a clear
        // bit uses the set the previous block left behind, and in a solid
        // chain that block can be another member's). Skipping the block
        // left the older set in force, and the next member decoded under
        // it: 239 members of 4,878 failed their checksum on a Python tree
        // packed that way, which reference `unrar t` passes whole (27 Sep
        // 2026, `tests::zero_byte_member_tables`).
        if unpacked_size == 0 {
            self.carry_empty_member_tables(packed, sink);
            return self.finish_member(unpacked_size, sink);
        }

        // THE SOLID CHAIN'S DECODE-AHEAD (see `ahead`). A member whose
        // symbols another thread has already decoded is applied straight
        // from its tapes. Everything a decoded operation CONSUMES still
        // happens here, on this thread, between the `begin_member` above
        // and the `finish_member` below, so the member's filter base, its
        // declared bound and its errors are formed exactly where they were.
        #[cfg(feature = "parallel")]
        if let Some((want, offered)) = self.ahead.front() {
            // The claim is on the CONTENT, so the whole member has to be in
            // hand. The LENGTH to ask for is the offer's own, and one byte
            // past it is what says the source held more than the offer did:
            // a member that fills the ask is not the member that was
            // offered, whatever its first bytes are.
            let claimed = if offered == unpacked_size {
                packed.fill(want + 1)?;
                let have = packed.available();
                if have.len() == want {
                    self.ahead.claim(have, unpacked_size, algorithm)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(mut work) = claimed {
                // Counts the members the lever actually reached, which is
                // the one thing about it no output byte can show. Compiled
                // out entirely without `h2-probes`; see `crate::probe`.
                #[cfg(feature = "h2-probes")]
                crate::probe::note_ahead_claim();
                let outcome = self.apply_ahead(&mut work, unpacked_size, sink, packed);
                self.ahead.give(work);
                outcome?;
                return self.finish_member(unpacked_size, sink);
            }
        }

        #[cfg(feature = "parallel")]
        if self.wants_tape(unpacked_size) {
            self.member_streamed(packed, unpacked_size, sink)?;
            return self.finish_member(unpacked_size, sink);
        }

        // EVERY BLOCK THE MEMBER OWNS, to the one flagged last, and not
        // only until the declared size is produced (SPEC-H2 3.1, amended
        // on 28 Sep 2026): the symbols past the declared end are applied to
        // the window and the repeat state, and the window's drain caps the
        // output. Before that change this loop stopped at the declared size
        // and clamped the operation that crossed it, so the next member of
        // a solid stream began that many bytes early and decoded to the
        // wrong bytes where reference `unrar` passes it
        // (`rar50/solid_interior_match_overrun.rar`).
        loop {
            packed.fill(MAX_BLOCK_HEADER)?;
            let want = block::extent_hint(packed.available());
            packed.fill(want)?;
            let located = block_in_hand(packed.available()).and_then(|block| {
                if packed.available().len() < block.past() {
                    Err(fault::truncated())
                } else {
                    Ok(block)
                }
            });
            let block = match located {
                Ok(block) => block,
                // A block wholly PAST the declared end whose header fails
                // (its check byte, or a size that runs past the packed
                // data) is not decoded, the member's decode ends here and
                // the member passes, its output being complete; the next
                // member continues from the window as it stands (SPEC-H2
                // 3.1, 28 Sep 2026). Before the
                // declared end it fails the member as always.
                Err(_) if self.window.produced() >= unpacked_size => break,
                Err(err) => return Err(err),
            };
            let available = packed.available();

            let payload = block.payload(available);
            let mut bits = BitReader::new(payload, block.bits());
            // A block wholly PAST the declared end whose TABLES do not read
            // (over-subscribed, cut by the block's end, or a table read
            // empty that the block's first symbol needs): none of it
            // applies, the member's decode ends here and it passes, and
            // the set in force is DROPPED, so a later member that leans on
            // the carried set fails `EmptyTable` (SPEC-H2 3.1, the bullet
            // of 28 Sep 2026). Before the declared end it fails the member
            // as always. Asked once a block, at its header and at its end.
            let began = self.window.produced();
            let past_end = block.carries_tables() && began >= unpacked_size;
            if block.carries_tables() {
                match self.read_tables(&mut bits) {
                    Ok(()) => {}
                    Err(_) if past_end => {
                        self.release_tables();
                        break;
                    }
                    // Before the declared end a table CUT by its block's
                    // end leaves the member short, as a cut symbol does:
                    // one kind on every arm (the tape path answers its
                    // deferred table failure through the same door).
                    Err(err) => return self.surplus_tail(Err(err), unpacked_size),
                }
            }
            // A first block with the table bit clear and no tables carried
            // is `EmptyTable` on its first symbol (section 3.2, V5-NOTABLE).
            let Some(tables) = self.current.clone() else {
                return Err(fault::empty_table());
            };

            // Preserve the ordinary decoder's original caller context.
            let decoded = if unpacked_size >= 65536
                && bits.remaining() >= 32768
                && serial_batch::admits(&tables)
            {
                serial_batch::dispatch(
                    &tables,
                    &mut self.state,
                    &mut self.window,
                    &mut self.filters,
                    &mut bits,
                    unpacked_size,
                    sink,
                )
            } else {
                decode_block(
                    &tables,
                    &mut self.state,
                    &mut self.window,
                    &mut self.filters,
                    &mut bits,
                    unpacked_size,
                    sink,
                )
            };
            if past_end && self.window.produced() == began && empty_table(&decoded) {
                drop(tables);
                self.release_tables();
                break;
            }
            self.surplus_tail(decoded, unpacked_size)?;

            packed.advance(block.past());
            if block.ends_member() {
                break;
            }
        }

        self.finish_member(unpacked_size, sink)
    }

    /// The tape path's width for this member: the carried policy
    /// (`tape::workers`, nothing below `MT_MIN_OUTPUT`), or, for a member
    /// continuing a solid chain with the lever on, the same width from
    /// the lever's floor ([`SOLID_TAPE_ENV`]).
    #[cfg(feature = "parallel")]
    pub(super) fn tape_workers(&self, unpacked: u64) -> usize {
        match self.chain_tape_floor {
            Some(floor) if self.continuing && unpacked >= floor => {
                tape::workers(u64::MAX, self.max_workers, self.width_stated)
            }
            _ => tape::workers(unpacked, self.max_workers, self.width_stated),
        }
    }

    /// Whether this member takes the parallel arm.
    #[cfg(feature = "parallel")]
    pub(super) fn wants_tape(&self, unpacked: u64) -> bool {
        match self.parallel {
            ParallelMode::Off => false,
            ParallelMode::On => true,
            ParallelMode::Auto => self.tape_workers(unpacked) > 0,
        }
    }

    /// The parallel arm: locate the blocks of one CHUNK of the chain on
    /// this thread, decode waves of them into tapes on the workers, and
    /// apply the tapes in archive order here (section 3.8). Answers how
    /// many packed bytes it used, and whether the member is finished.
    ///
    /// The wave is twice the worker count, so the pool always has a block
    /// to start while the apply stage walks the one before it, and the
    /// tapes in flight are bounded by the wave and by the carried caps.
    #[cfg(feature = "parallel")]
    pub(super) fn member_parallel<S: LzSink>(
        &mut self,
        packed: &[u8],
        unpacked: u64,
        sink: &mut S,
        tail: bool,
    ) -> Result<(usize, bool)> {
        let mut plan = std::mem::take(&mut self.plan);
        let outcome = self.member_planned(&mut plan, packed, unpacked, sink, tail);
        plan.clear();
        self.plan = plan;
        outcome
    }

    /// The tape path over a source that arrives in pieces.
    ///
    /// Spec F 7.3.10 forbids the one-pass path buffering a whole member,
    /// and the plan of section 3.8 indexes the packed bytes it is handed,
    /// so the chain is planned a CHUNK at a time: enough bytes for a wave
    /// of blocks, decoded, applied, advanced past, then the next chunk. A
    /// chunk always ends on a block boundary and the decoder's own state
    /// is what carries across one, so where the chunks fall cannot change
    /// a byte. A chunk holding no whole block at all doubles the request,
    /// up to the largest a RAR 5 block may be (section 4.1: a 24 bit
    /// payload length), so the walk always advances.
    #[cfg(feature = "parallel")]
    pub(super) fn member_streamed<P: PackedSource, S: LzSink>(
        &mut self,
        packed: &mut P,
        unpacked: u64,
        sink: &mut S,
    ) -> Result<()> {
        #[cfg(feature = "wait-census")]
        let _census = crate::probe::census::at(crate::probe::census::BIG_MEMBERS);
        // A quarter of what the budget leaves this member's width
        // (`width_room`), where that is under the chunk: a window that
        // takes most of a NAMED budget is streamed in pieces the rest of
        // it holds, and a block larger than the piece grows the ask below
        // as it always did. A default budget leaves the chunk as it was.
        let mut want = STREAM_CHUNK
            .min(usize::try_from(self.working_limit / 4).unwrap_or(usize::MAX))
            .max(STREAM_CHUNK_FLOOR);
        loop {
            {
                #[cfg(feature = "wait-census")]
                let _census = crate::probe::census::at(crate::probe::census::FILL);
                packed.fill(want)?;
            }
            // The LAST chunk is one the source says ends the member, not
            // one that came back short: a source may hold less than was
            // asked (its cap), and a short chunk that is not the end is
            // decoded, advanced past and followed by the next.
            let tail = packed.available().len() < want && packed.exhausted();
            let (used, done) = self.member_parallel(packed.available(), unpacked, sink, tail)?;
            packed.advance(used);
            if done || tail {
                return Ok(());
            }
            if used == 0 {
                if want >= STREAM_CHUNK_MAX {
                    // No block this large exists: the header the walk is
                    // sitting on cannot be one.
                    return Err(fault::truncated());
                }
                want = (want * 2).min(STREAM_CHUNK_MAX);
            }
        }
    }

    #[cfg(feature = "parallel")]
    pub(super) fn member_planned<S: LzSink>(
        &mut self,
        plan: &mut tape::Plan,
        packed: &[u8],
        unpacked: u64,
        sink: &mut S,
        tail: bool,
    ) -> Result<(usize, bool)> {
        {
            #[cfg(feature = "wait-census")]
            let _census = crate::probe::census::at(crate::probe::census::PLAN);
            tape::plan(packed, self.current.is_some(), plan)?;
        }
        // THE CHUNK'S OWN BLOCK COUNT, read before anything caps it.
        // The narrow-breadth measurement leaves a rule keyed on this
        // quantity open and could not test it for want of a counter; the
        // `lanes` twenty lines below is capped by the width, by the wave
        // and by the chain at once, so it says nothing about the chain.
        // Compiled out entirely without `h2-probes`; see
        // `crate::probe::note_chunk_plan`, whose doc has the rest.
        //
        // ONE CALL, TWO COUNTERS. The bimodality work added
        // `probe::note_planned` at this exact line for its own question,
        // and `note_chunk_plan` calls it rather than standing beside it:
        // one planned chunk should be one notification, or the next
        // reader has to work out whether two adjacent calls count the
        // same event. `planned()` and `reset_planned()` are unchanged
        // and still independent of the counters below them.
        #[cfg(feature = "h2-probes")]
        crate::probe::note_chunk_plan(plan.blocks.len(), plan.groups.len());
        // THE CHUNK IS THE UNIT OF THE RESERVATION. The lanes below live
        // inside one `std::thread::scope` that joins before this returns,
        // so a grant taken here is given back at the end of this chunk
        // and a member that took the whole ceiling while the pool was
        // quiet narrows as soon as its neighbours arrive (8.3, and
        // `read::lanes`). Without a budget the width is the ceiling the
        // caller was given, which is the sequential path and the
        // divide-at-dispatch arrangement both.
        let most = self.tape_workers(unpacked).max(1);
        let want = self.tape_grow.map_or(most, |width| width.lanes(most));
        // The handle is cloned out first so the grant borrows IT and not
        // `self`, which the decode below needs mutably.
        #[cfg(feature = "parallel")]
        let budget = self.budget.clone();
        let grant = budget.as_ref().map(|b| b.take(want));
        let width = grant.as_ref().map_or(want, |g| g.lanes());
        let in_flight = self.wave_blocks.unwrap_or(width * 2).max(1);
        // THE STAGE SIZES ITSELF TO THE WORK (API section 8.2): a lane per
        // block it actually has, never more, and never a lane for a pool
        // thread that would have nothing to decode. A chain of one block
        // gets no lane at all and no thread is spawned.
        // THE TAPE UNITS (SPEC-API 8.2): the lanes take runs of
        // consecutive blocks, so the stage sizes itself to units, not blocks.
        // The unit is CHARGED at the lanes this chunk may open and shrinks
        // to what the working limit leaves them, down to one block a unit,
        // and a cut that would leave the chunk fewer lanes than one block a
        // unit gives is made one block a unit instead.
        let charged = width.min(in_flight);
        let unit = self
            .tape_unit
            .unwrap_or_else(tape::unit_bytes)
            .min(tape::unit_bytes_within_budget(self.working_limit, charged));
        plan.cut_units_for_lanes(unit, charged);
        let lanes = charged.min(plan.units.len());
        let mut used = 0usize;
        let done = if self.overlap && lanes > 1 {
            let (done, waited, counted) =
                self.member_piped(plan, packed, unpacked, sink, lanes, &mut used)?;
            // The members being decoded right now, this one among them:
            // one where no budget is shared (`read::lanes`).
            let abreast = budget.as_ref().map_or(1, |b| b.members()).max(1);
            if tape::trace() {
                eprintln!(
                    "tape-width lanes {lanes} waited {waited} counted {counted} most {most} members {abreast}"
                );
            }
            if let Some(width) = self.tape_grow.as_mut() {
                width.after_chunk_beside(lanes, waited, counted, most, abreast);
            }
            done
        } else {
            // With no second lane to run, a wave is a queue of one: the
            // blocks decode and apply on this thread, one at a time, and
            // nothing is handed to the caller's pool for it to watch.
            let wave_len = if lanes > 1 { in_flight } else { 1 };
            #[cfg(feature = "wait-census")]
            let _census = crate::probe::census::at(crate::probe::census::ONE_THREAD);
            self.member_wave_at_a_time(plan, packed, unpacked, sink, wave_len, &mut used)?
        };
        // The lanes are joined and the grant goes back to the budget, so
        // the next member to ask sees what this chunk was holding.
        drop(grant);
        // A block wholly PAST the declared end whose header failed: not
        // decoded, the member's decode ends here and it passes (SPEC-H2
        // 3.1), as the serial walk answers it. A
        // `Truncated` locate is that failure only on the member's LAST
        // chunk: on any other it is a block the next chunk holds whole.
        let header_failed = plan
            .failure
            .as_ref()
            .is_some_and(|failure| tail || !matches!(failure.kind(), crate::ErrorKind::Truncated));
        if !done && header_failed && self.window.produced() >= unpacked {
            plan.failure = None;
            return Ok((used, true));
        }
        if !tail {
            // A header that is CORRUPT, not cut: its check byte, or the
            // size width the format does not have. More bytes cannot cure
            // it, every block before it has been applied and the member
            // still owes bytes, so it is raised here, as the serial walk
            // raises it. Left to the next chunk it planned no block, the
            // caller asked for more until no block that large exists, and
            // the member was called `Truncated` where it is damaged.
            if !done && header_failed {
                if let Some(failure) = plan.failure.take() {
                    return Err(failure);
                }
            }
            // The chunk ran out, not the chain: a block the plan could not
            // locate inside it is the next chunk's first block, and the
            // caller comes back with more bytes.
            return Ok((used, done));
        }
        if !done {
            // The chain ran out before its block flagged last. The serial
            // arm would have asked for the next block here and met exactly
            // this: the header that did not parse, or the end of the
            // packed bytes. A chain that ends on a block flagged LAST is
            // short rather than truncated, and `finish_member` says so.
            if let Some(failure) = plan.failure.take() {
                return Err(failure);
            }
            // Neither: the packed bytes ended at a block's edge with no
            // block flagged last. The member is whole if its declared
            // size is produced (SPEC-H2 3.2) and cut if it is not.
            if !plan.saw_last && self.window.produced() < unpacked {
                return Err(fault::truncated());
            }
        }
        Ok((used, true))
    }

    /// The bulk synchronous driver: decode a wave, stop, apply it, start
    /// the next. A chain of ONE wave has nothing to overlap with and takes
    /// this whatever the setting, which is every small member and every
    /// chunk of a streamed one that holds a single wave of blocks.
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn member_wave_at_a_time<S: LzSink>(
        &mut self,
        plan: &tape::Plan,
        packed: &[u8],
        unpacked: u64,
        sink: &mut S,
        wave_len: usize,
        used: &mut usize,
    ) -> Result<bool> {
        // A WAVE OF ONE is a member decoded on this thread alone, and it
        // takes the one-pass decode: each block's symbols applied as they
        // are read, with no tape between (`onepass`).
        if wave_len == 1 && onepass::on() {
            return self.member_one_thread(plan, packed, unpacked, sink, used);
        }
        let mut wave = self.waves.pop().unwrap_or_default();
        let carried = self.current.clone();
        let mut at = 0usize;
        let mut outcome = Ok(false);
        while at < plan.blocks.len() {
            let end = (at + wave_len).min(plan.blocks.len());
            tape::decode_wave_into(
                plan,
                packed,
                self.algorithm,
                carried.as_ref(),
                at..end,
                &mut self.tapes,
                &mut wave,
            );
            outcome = self.apply_wave(plan, packed, &mut wave, at, unpacked, sink, used);
            if !matches!(outcome, Ok(false)) {
                break;
            }
            at = end;
        }
        self.waves.push(wave);
        outcome
    }

    /// The planned chunk's blocks decoded ON THIS THREAD by the serial loop
    /// and its one-pass region (`onepass`), in place of a wave of one: a
    /// block is decoded and applied at once, and no tape is written or
    /// walked.
    ///
    /// Everything [`Rar5Lz::apply_one`] does around a tape is done here in
    /// the same order: the block's table set from its group, the set made
    /// current, a set that did not read raised as the tape's deferred
    /// failure is (through [`Rar5Lz::surplus_tail`]), the packed bytes
    /// used, the groups passed released, and the member done at its block
    /// flagged last. The symbols are the serial arm's, which the
    /// serial-against-parallel property test holds to the tape's bytes and
    /// errors (SPEC-H2 3.8); a distance past `u32` needs no park here.
    #[cfg(feature = "parallel")]
    pub(super) fn member_one_thread<S: LzSink>(
        &mut self,
        plan: &tape::Plan,
        packed: &[u8],
        unpacked: u64,
        sink: &mut S,
        used: &mut usize,
    ) -> Result<bool> {
        let carried = self.current.clone();
        let mut spare: Option<tape::BlockTape> = None;
        // Set where a block past the declared end has tables that do not
        // read: the walk ends there and the member is done.
        let mut dropped = false;
        // The filter transforms go to a pool task as the tape's walk sends
        // them (`tape::apply`): one thread decodes, and a transform the
        // drain hands away runs beside it, as it did for a wave of one.
        self.filters.offload = filters::offload_wanted();
        for (index, block) in plan.blocks.iter().enumerate() {
            let group_index = plan.group_of[index];
            match tape::block_tables(plan, packed, self.algorithm, carried.as_ref(), index) {
                // A SET THE TAPE'S LITERAL BATCH TAKES keeps the tape: the
                // block decoded by the batch and applied at once, exactly the
                // wave of one it was. On compressed media (almost all
                // length-8 literals) the batch's seven codes a window beat
                // both the region and the serial loop's own batch: the S8
                // set at -mt1 on a Zen 4, 1,596M cycles by the tape against
                // 1,740M one pass and 1,750M to 1,782M by the serial batch
                // (the one-pass decode measurement).
                Ok((tables, _)) if tape_batch_takes(&tables) => {
                    let tape = spare.get_or_insert_with(|| self.tapes.take());
                    let held = tape::decode_one_dispatch(
                        plan,
                        packed,
                        self.algorithm,
                        carried.as_ref(),
                        index,
                        tape,
                    );
                    if self
                        .apply_one(plan, packed, tape, held, None, index, unpacked, sink, used)?
                    {
                        self.tapes.give(spare.take().expect("taken above"));
                        return Ok(true);
                    }
                    continue;
                }
                Ok((tables, from)) => {
                    // A block decoded here is a decoding unit, as a tape's
                    // is (`tape::decode_one`); the probe counts how wide the
                    // decode ran. Compiled out without `h2-probes`.
                    #[cfg(feature = "h2-probes")]
                    let _worker = crate::probe::WorkerGuard::enter();
                    self.current = Some(tables.clone());
                    let began = self.window.produced();
                    let mut bits = BitReader::new(block.payload(packed), block.bits());
                    bits.seek(from);
                    // The serial arm's choice between its two loops.
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
                    // A table read EMPTY that the first symbol of a block
                    // wholly past the declared end needs: tables that do
                    // not read, answered as the serial walk answers them
                    // (SPEC-H2 3.1).
                    if block.carries_tables()
                        && began >= unpacked
                        && self.window.produced() == began
                        && empty_table(&decoded)
                    {
                        dropped = true;
                        break;
                    }
                    self.surplus_tail(decoded, unpacked)?;
                }
                // A block wholly PAST the declared end whose tables do
                // not read is not decoded: the member's decode ends here,
                // it passes, and the set in force is dropped (SPEC-H2 3.1,
                // the bullet of 28 Sep 2026), as the serial walk answers
                // it. Before this a table cut by its block's end passed
                // there and the walk went on under the stale set.
                Err(_) if block.carries_tables() && self.window.produced() >= unpacked => {
                    dropped = true;
                    break;
                }
                Err(err) => self.surplus_tail(Err(err), unpacked)?,
            }
            *used = block.past();
            plan.release_below(group_index);
            if block.ends_member() {
                if let Some(tape) = spare {
                    self.tapes.give(tape);
                }
                return Ok(true);
            }
        }
        if let Some(tape) = spare {
            self.tapes.give(tape);
        }
        if dropped {
            self.release_tables();
        }
        Ok(dropped)
    }

    /// The PIPELINE: `lanes` decode threads run ahead of the serial
    /// apply stage, each on its own arithmetic progression of the chain.
    ///
    /// **What this replaced, and the measurement that asked for it.** The
    /// driver here was a WAVE with a barrier: `2 * W` blocks handed to the
    /// caller's thread pool, every one of them waited for, then applied,
    /// then the next wave. A wave of that size is about 60 microseconds of
    /// work per thread on a real archive, so the barrier fell every 60
    /// microseconds and about two thousand times per member; a pool wider
    /// than the wave then spent as long looking for work as doing it. On
    /// 19 Sep 2026 a sampling profile of `rarfast t` over a 768 MiB solid
    /// set put HALF of every thread sample in the pool's idle spin
    /// (`swtch_pri`, reached from rayon's `wait_until_cold`), which is why
    /// a wider pool cost twice the wall and twelve times the CPU of a
    /// narrow one (measured 19 Sep 2026).
    ///
    /// **Why lanes and not a wider wave.** The cure for a barrier is to
    /// remove it, not to move it: API section 8.2 bounds the blocks
    /// decoded at once at `2 * W`, so a wave can never be made coarse
    /// enough to amortise its own barrier. A lane instead decodes, hands
    /// its tape over and starts the next block without waiting for any
    /// other lane, so nothing synchronises but the hand-over itself.
    ///
    /// **Why the lanes are this stage's own threads.** API section 8.3
    /// lets the engine spawn scoped threads it joins before the call
    /// returns, and the number alive at once is this stage's `lanes`,
    /// itself at most `max_workers` and at most the carried worker
    /// ceiling. A lane BLOCKS when the apply stage is behind, which a
    /// task on the caller's pool must never do: a pool narrower than
    /// `lanes` would deadlock, and the pool is the caller's to size. Not
    /// touching it is also what makes the width of the caller's pool stop
    /// mattering, which was the defect.
    ///
    /// **The bound, in tapes.** Lane `k` takes blocks `k`, `k + lanes`,
    /// `k + 2 * lanes` and so on, and hands each to the apply stage down a
    /// channel of ONE. So a lane holds at most the tape it is filling and
    /// the tape it has handed over: `2 * lanes` tapes alive, with `lanes`
    /// blocks decoding at once, inside section 8.2's `2 * W` blocks and
    /// `4 * W` tapes. The apply stage reads the lanes round robin, which
    /// is archive order by construction and needs no reordering buffer.
    ///
    /// **What the decode side needs from the stream, and why it is
    /// nothing.** The only stream state a decode can consult is the table
    /// set a group with no first block stands for, and there is exactly
    /// one such group: the chain's first, which ends at the first block
    /// that carries tables. Every group after it builds its set from its
    /// own payload. So the set in force for every group the decode side
    /// can ask about is the one this chunk BEGAN with, and it is in hand
    /// before a single byte is applied.
    ///
    /// **Errors.** Nothing here changes which error a member raises or
    /// where. A block decoded ahead of the apply point defers its failure
    /// into its own tape exactly as before (section 3.8, consequence 1),
    /// the apply stage meets the tapes in archive order, and it is the
    /// first block the member genuinely REACHES that raises. Blocks
    /// decoded past the stop are dropped unread.
    ///
    /// **Answers the apply stage's waits beside whether the member
    /// finished**: of the units past each lane's first (which every lane
    /// makes the apply wait for, being just started), how many were not
    /// yet decoded when the apply reached them, and how many there were.
    /// That is what the default width moves on ([`tape::Width`]).
    /// Asking the channel before waiting on it changes no byte and no
    /// order: it is the same receive, taken without a park when it can be.
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn member_piped<S: LzSink>(
        &mut self,
        plan: &tape::Plan,
        packed: &[u8],
        unpacked: u64,
        sink: &mut S,
        lanes: usize,
        used: &mut usize,
    ) -> Result<(bool, usize, usize)> {
        use std::sync::mpsc;

        let algorithm = self.algorithm;
        let carried = self.current.clone();
        let mut pool = std::mem::take(&mut self.tapes);
        // Two tapes per lane, out of the pool, as the per-block form always
        // had. A lane whose units span several blocks needs more tapes in
        // flight (up to three units' worth) and allocates the rest FRESH,
        // so they grow only to what its own blocks need; and only
        // `POOL_TAPES_PER_LANE` of each lane's tapes go back to the pool at
        // the end of the chunk, the rest being dropped. Giving every tape
        // back grew the pool by the chunk (about 300 MB a lane at 256 KiB
        // units), and seeding a lane from the pool with a unit's worth
        // handed it tapes still holding the capacity of big blocks from
        // earlier members (+54 MiB on bin4g) (29 Sep 2026, the
        // tape unit measurement).
        let mut seed: Vec<Vec<tape::BlockTape>> = (0..lanes)
            .map(|_| (0..POOL_TAPES_PER_LANE).map(|_| pool.take()).collect())
            .collect();
        let mut spares: Vec<Vec<tape::BlockTape>> = Vec::with_capacity(lanes);
        let mut done = false;
        let mut result = Ok(());
        let mut waited = 0usize;
        let mut counted = 0usize;
        // THE SYMBOL PASS (`symbols`), decided once for the chunk on this
        // thread and handed to the lanes: only a small dictionary in a ring
        // at least twice its size, and only where the knob is on.
        let gather = symbols::enabled() && symbols::fits(self.declared, self.window.ring_bytes());
        // Which form of the lane build, decided here once for the chunk too.
        let lean = gather && symbols::lean_form();
        // THE REPEATS RESOLVED ON THE LANE only where the member has lanes
        // to spare for the pass: at fewer, the lanes are the critical path
        // and the pass lengthens it (the repeat residue measurement).
        let resolve = lanes >= tape::resolve_min_lanes();
        let declared = self.declared;

        // One unit's decoded blocks, handed over in ONE message: a tape
        // per block, its table set and its gathered symbols. The same `Vec`
        // comes back emptied of table sets, so a steady state allocates
        // nothing.
        type Decoded = (
            tape::BlockTape,
            Option<Arc<Tables>>,
            Option<Box<symbols::Symbols>>,
        );
        let units = &plan.units;
        let unit_count = units.len();
        // The lanes the host started, when it refused one (`crate::threads`):
        // the chunk is then decoded again below, as wide as that, and not
        // applied here at all.
        let mut refused: Option<usize> = None;
        #[cfg(feature = "wait-census")]
        let _census_lanes = crate::probe::census::by(crate::probe::census::LANES, lanes);
        std::thread::scope(|scope| {
            #[cfg(feature = "wait-census")]
            let census_spawn = crate::probe::census::at(crate::probe::census::SPAWN);
            let mut ready = Vec::with_capacity(lanes);
            let mut spent = Vec::with_capacity(lanes);
            let mut handles = Vec::with_capacity(lanes);
            for (lane, seed) in seed.iter_mut().enumerate() {
                #[cfg(not(feature = "h2-stage-probe"))]
                let depth = 1;
                #[cfg(feature = "h2-stage-probe")]
                let depth = self.probe_channel_depth;
                let (tape_tx, tape_rx) = mpsc::sync_channel::<Vec<Decoded>>(depth);
                let (spent_tx, spent_rx) = mpsc::channel::<Vec<Decoded>>();
                let mut held = std::mem::take(seed);
                let mut held_symbols: Vec<Box<symbols::Symbols>> = Vec::new();
                let mut held_units: Vec<Vec<Decoded>> = Vec::new();
                let carried = carried.clone();
                let spawned = crate::threads::scoped(scope, move || {
                    // Counts how wide the decode was SPREAD, in threads
                    // alive, which is the form API 8.3 states its
                    // scoped-thread constant in. Compiled out entirely
                    // without `h2-probes`; see `crate::probe`.
                    #[cfg(feature = "h2-probes")]
                    let _lane = crate::probe::LaneGuard::enter();
                    // The units the apply stage has finished with come
                    // back here, tapes and all.
                    let take_back = |held: &mut Vec<tape::BlockTape>,
                                     held_symbols: &mut Vec<Box<symbols::Symbols>>,
                                     held_units: &mut Vec<Vec<Decoded>>,
                                     mut unit: Vec<Decoded>| {
                        for (tape, _, gathered) in unit.drain(..) {
                            held.push(tape);
                            held_symbols.extend(gathered);
                        }
                        held_units.push(unit);
                    };
                    let mut next = lane;
                    while next < unit_count {
                        for unit in spent_rx.try_iter() {
                            take_back(&mut held, &mut held_symbols, &mut held_units, unit);
                        }
                        let mut decoded = held_units.pop().unwrap_or_default();
                        let (first, end) = units[next];
                        #[cfg(feature = "wait-census")]
                        let census_decode =
                            crate::probe::census::at(crate::probe::census::LANE_DECODE);
                        for at in first..end {
                            let mut tape = held.pop().unwrap_or_default();
                            #[cfg(feature = "h2-probes")]
                            let decode_from = std::time::Instant::now();
                            let tables = tape::decode_one_dispatch(
                                plan,
                                packed,
                                algorithm,
                                carried.as_ref(),
                                at,
                                &mut tape,
                            );
                            // The block's operations walked into symbols
                            // HERE, on the lane, so the apply stage only
                            // gathers. Inside the lane's decode time on
                            // purpose: it is lane work.
                            let gathered = if gather {
                                let mut gathered = held_symbols.pop().unwrap_or_default();
                                if lean {
                                    gathered.build_lean(&tape, declared);
                                } else {
                                    gathered.build(&tape, declared);
                                }
                                Some(gathered)
                            } else {
                                // THE REPEATS RESOLVED ON THE LANE, where no
                                // symbol pass takes the block: lane work too.
                                if resolve {
                                    tape::resolve_repeats(&mut tape);
                                }
                                None
                            };
                            #[cfg(feature = "h2-probes")]
                            crate::probe::note_lane_decode(decode_from.elapsed().as_nanos() as u64);
                            decoded.push((tape, tables, gathered));
                        }
                        #[cfg(feature = "wait-census")]
                        drop(census_decode);
                        #[cfg(feature = "h2-probes")]
                        let handover_from = std::time::Instant::now();
                        #[cfg(feature = "wait-census")]
                        let census_send = crate::probe::census::at(crate::probe::census::LANE_SEND);
                        let sent = tape_tx.send(decoded);
                        #[cfg(feature = "wait-census")]
                        drop(census_send);
                        #[cfg(feature = "h2-probes")]
                        crate::probe::note_lane_wait(handover_from.elapsed().as_nanos() as u64);
                        if sent.is_err() {
                            // The apply stage has stopped: the member
                            // finished, or it raised. Everything decoded
                            // past that point is discarded unread.
                            break;
                        }
                        next += lanes;
                    }
                    drop(tape_tx);
                    for unit in spent_rx.try_iter() {
                        take_back(&mut held, &mut held_symbols, &mut held_units, unit);
                    }
                    held
                });
                match spawned {
                    Ok(handle) => handles.push(handle),
                    Err(_) => {
                        refused = Some(lane);
                        break;
                    }
                }
                ready.push(tape_rx);
                spent.push(spent_tx);
            }
            #[cfg(feature = "wait-census")]
            drop(census_spawn);
            'units: for (unit, &(first, _)) in units.iter().enumerate() {
                if refused.is_some() {
                    // Nothing is applied from a chunk whose lanes did not
                    // all start: the lanes that did see their receivers go
                    // below and stop.
                    break;
                }
                let lane = unit % lanes;
                // A lane that has stopped early can only be one that saw
                // the apply stage go away, which is after this loop.
                #[cfg(feature = "h2-probes")]
                let wait_from = std::time::Instant::now();
                #[cfg(feature = "wait-census")]
                let census_wait = crate::probe::census::at(crate::probe::census::APPLY_WAIT);
                let received = if unit < lanes {
                    ready[lane].recv()
                } else {
                    counted += 1;
                    match ready[lane].try_recv() {
                        Ok(decoded) => Ok(decoded),
                        Err(mpsc::TryRecvError::Empty) => {
                            waited += 1;
                            ready[lane].recv()
                        }
                        Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::RecvError),
                    }
                };
                #[cfg(feature = "h2-probes")]
                crate::probe::note_apply_wait(wait_from.elapsed().as_nanos() as u64);
                #[cfg(feature = "wait-census")]
                drop(census_wait);
                let Ok(mut decoded) = received else {
                    break;
                };
                #[cfg(feature = "wait-census")]
                let census_busy = crate::probe::census::at(crate::probe::census::APPLY_BUSY);
                // The unit's blocks, applied in archive order at their own
                // indices, exactly as the per-block hand-over applied them.
                let mut stop = false;
                for (offset, (tape, tables, gathered)) in decoded.iter_mut().enumerate() {
                    #[cfg(feature = "h2-probes")]
                    let apply_from = std::time::Instant::now();
                    let outcome = self.apply_one(
                        plan,
                        packed,
                        tape,
                        tables.take(),
                        gathered.as_deref(),
                        first + offset,
                        unpacked,
                        sink,
                        used,
                    );
                    #[cfg(feature = "h2-probes")]
                    crate::probe::note_apply_busy(apply_from.elapsed().as_nanos() as u64);
                    match outcome {
                        Ok(false) => {}
                        Ok(true) => {
                            done = true;
                            stop = true;
                            break;
                        }
                        Err(err) => {
                            result = Err(err);
                            stop = true;
                            break;
                        }
                    }
                }
                #[cfg(feature = "wait-census")]
                drop(census_busy);
                let _ = spent[lane].send(decoded);
                if stop {
                    break 'units;
                }
            }
            #[cfg(feature = "wait-census")]
            let _census_join = crate::probe::census::at(crate::probe::census::JOIN);
            // Drop the receiving ends so a lane parked in `send` wakes,
            // and the sending ends so its own drain cannot block.
            drop(ready);
            drop(spent);
            for handle in handles {
                match handle.join() {
                    Ok(held) => spares.push(held),
                    // Section 4.3 says this package does not panic. If it
                    // ever does, on a lane, the panic is the caller's to
                    // see: swallowing it here would turn a bug into a
                    // silently truncated member.
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }
        });
        for lane in spares {
            for tape in lane.into_iter().take(POOL_TAPES_PER_LANE) {
                pool.give(tape);
            }
        }
        if let Some(started) = refused {
            // The seeds no lane took go back with the rest.
            for tape in seed.into_iter().flatten() {
                pool.give(tape);
            }
            self.tapes = pool;
            // The same chunk, from its first block, at the width the host
            // gave: nothing of it reached the window, so this is the chunk
            // decoded afresh. One lane is the serial form below, which
            // counts no unit waited for, so it tells the width nothing.
            if started > 1 {
                return self.member_piped(plan, packed, unpacked, sink, started, used);
            }
            return self
                .member_wave_at_a_time(plan, packed, unpacked, sink, 1, used)
                .map(|done| (done, 0, 0));
        }
        self.tapes = pool;
        result.map(|()| (done, waited, counted))
    }

    /// Everything a member owes when its blocks are done: what is held
    /// leaves for the sink, and a member the chain left short says so.
    pub(super) fn finish_member<S: LzSink>(
        &mut self,
        unpacked_size: u64,
        sink: &mut S,
    ) -> Result<()> {
        self.window.drain(&mut *sink, &mut self.filters, true)?;
        // What LEFT for the sink, not what was produced: a member whose
        // bytes a pending filter kept back is as short as one whose chain
        // ended early, and is never reported whole (section 3.1). Found on
        // 27 Sep 2026 by `fuzz:rar5_oracle_stream`: two records on one span
        // answered a 259 byte member OK with 230 bytes on every arm.
        if self.window.emitted() < unpacked_size {
            return Err(fault::incomplete_member());
        }
        Ok(())
    }
}
