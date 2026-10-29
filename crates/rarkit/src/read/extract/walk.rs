//! The walk over an archive's members: its phases, and what it offers a
//! driver (which members go to a worker, which batch, which split).

use super::*;

/// The walk of one operation and everything it carries from one member to
/// the next, WHICHEVER DRIVER is running it.
///
/// Held apart from the driver so that one walk may be run by two drivers
/// in turn (`read::sequential`): a PHASE runs the walk under one driver
/// until that driver hands off ([`Driver::hands_off`]) before a member,
/// which is kept here unopened, and the next phase's driver begins with
/// it. [`extract_driven`] runs one phase to the end.
pub(crate) struct Walking<'c, V: Volumes> {
    pub(super) walk: Walk<'c, V>,
    pub(super) cancel: Option<std::sync::Arc<AtomicBool>>,
    pub(super) policy: crate::MemoryPolicy,
    #[cfg(feature = "parallel")]
    pub(super) sink_is_file: Option<bool>,
    #[cfg(feature = "parallel")]
    pub(super) volumes_present: bool,
    /// One decoder per method and dictionary size for the whole operation
    /// (spec F 7.3.5).
    ///
    /// THE WALKING THREAD DECODES AT THE WHOLE READ WIDTH (API 8.4.2): a
    /// solid chain, a split member and anything no worker may take are
    /// decoded here, and the driver's lane budget is what shares the width
    /// with the members in flight beside them (8.3, `read::lanes`).
    pub(super) decoders: Decoders,
    /// One reusable buffer for the member name each `MemberInfo` borrows:
    /// one allocation for the whole operation, not one per member.
    pub(super) name_buf: Vec<u8>,
    /// Whether a member with its solid bit CLEAR has been seen: the chain
    /// starts at the most recent one (spec F 3.6).
    pub(super) chain_started: bool,
    /// ONE slot for the whole walk, filled in place. See `Block::empty`:
    /// the block is 352 bytes and the walk runs once per block.
    pub(super) slot: crate::read::block::Block,
    /// `slot` holds a member the last phase handed off before opening.
    pub(super) held: bool,
    /// [`Run`]'s own fields, carried between phases.
    pub(super) bytes: u64,
    pub(super) output_since_tick: u64,
    pub(super) scratch: Scratch,
    pub(super) blake: Option<Box<Blake2sp>>,
    /// What the drivers of finished phases closed.
    pub(super) closed: Closed,
}

impl<'c, V: Volumes> Walking<'c, V> {
    #[inline]
    pub(crate) fn begin(volumes: V, ctx: &'c mut ReadCtx) -> Result<Walking<'c, V>> {
        // `ReadOptions::workers` of zero is refused by name before anything
        // is spent, on the sequential path as on the concurrent one
        // (8.4.2, 8.4.4 test 6).
        ctx.options.refuse_no_workers()?;
        let cancel = ctx.options.cancel.clone();
        let policy = ctx.options.memory;
        // The seam's cost class, read here for the same reason `policy` and
        // `read_width` are: the walk borrows the context below (8.5).
        #[cfg(feature = "parallel")]
        let sink_is_file = ctx.options.sink_is_file;
        #[cfg(feature = "parallel")]
        let volumes_present = ctx.options.volumes_present;
        // Read before the walk borrows the context, and the same figure the
        // concurrent driver spends (8.4.2).
        let read_width = ctx.options.read_width();
        // The solid chain's decode-ahead lanes, read here for the same
        // reason.
        #[cfg(feature = "parallel")]
        let ahead_lanes = crate::read::lanes::ahead_lanes(ctx.options.workers, read_width);
        #[cfg_attr(not(feature = "parallel"), allow(unused_mut))]
        let mut decoders = Decoders {
            decode_width: read_width,
            width_stated: ctx.options.workers.is_some(),
            // Under a NAMED budget, and under the whole-process default
            // (`MemoryPolicy::keeps_residency`), the walk rebuilds its ring
            // small and gives every dropped one back (Shrink::Tight),
            // as the look-ahead's workers do: a ring
            // kept at its high-water, or freed into the allocator's cache,
            // is resident memory the budget does not see.
            shrink: if policy.keeps_residency() {
                Shrink::Tight
            } else {
                Shrink::Wide
            },
            ..Decoders::default()
        };
        // The solid chain's decode-ahead at the chain's own width unless
        // the caller stated one (`read::lanes::ahead_lanes`).
        #[cfg(feature = "parallel")]
        {
            decoders.ahead_lanes = Some(ahead_lanes);
        }
        Ok(Walking {
            walk: Walk::new(volumes, ctx),
            cancel,
            policy,
            #[cfg(feature = "parallel")]
            sink_is_file,
            #[cfg(feature = "parallel")]
            volumes_present,
            decoders,
            name_buf: Vec::new(),
            chain_started: false,
            slot: crate::read::block::Block::empty(),
            held: false,
            bytes: 0,
            output_since_tick: 0,
            scratch: Scratch::default(),
            blake: None,
            closed: Closed::default(),
        })
    }

    /// Run the walk under `driver` until the archive ends (`false`) or the
    /// driver hands off before a member (`true`), which is then held.
    #[inline]
    pub(crate) fn phase<D: Driver, P: Progress>(
        &mut self,
        driver: &mut D,
        progress: &mut P,
    ) -> Result<bool> {
        #[cfg(feature = "parallel")]
        {
            self.decoders.budget = driver.lane_budget();
        }
        if self.held {
            // The member held was reached under the last driver, after the
            // main header that says whether the archive is solid.
            driver.note_solid(self.walk.solid_archive);
        }
        let Walking {
            walk,
            cancel,
            policy,
            #[cfg(feature = "parallel")]
            sink_is_file,
            #[cfg(feature = "parallel")]
            volumes_present,
            decoders,
            name_buf,
            chain_started,
            slot,
            held,
            bytes,
            output_since_tick,
            scratch,
            blake,
            ..
        } = self;
        let cancel = cancel.as_deref();
        let gate: Gate<'_, P> = RefCell::new(progress);
        let mut run = Run {
            driver,
            bytes: *bytes,
            base: 0,
            output_since_tick: *output_since_tick,
            policy: *policy,
            #[cfg(feature = "parallel")]
            sink_is_file: *sink_is_file,
            #[cfg(feature = "parallel")]
            volumes_present: *volumes_present,
            scratch: std::mem::take(scratch),
            blake: blake.take(),
        };
        let outcome = (|| -> Result<bool> {
            loop {
                if !std::mem::take(held) && !walk.next_block_into(&gate, slot)? {
                    return Ok(false);
                }
                let block = &*slot;
                let is_member = matches!(&block.fields, Fields::File(f) if f.service.is_none());
                if is_member {
                    // BORROWED, not cloned: `block` outlives the call below
                    // and nothing in it moves, where cloning the fields
                    // copied the whole header once a member for no other
                    // reason than to hold it by value.
                    let Fields::File(file) = &block.fields else {
                        unreachable!("just matched");
                    };
                    if run.driver.hands_off(walk.solid_archive, file, block) {
                        *held = true;
                        return Ok(true);
                    }
                    let volume = walk.volume;
                    let mark = walk.arena_mark();
                    member(
                        &mut run,
                        walk,
                        &gate,
                        block,
                        file,
                        name_buf,
                        chain_started,
                        decoders,
                        cancel,
                    )?;
                    if walk.volume == volume {
                        walk.arena_reset(mark);
                    }
                    // What the driver handed the caller beside the walk,
                    // told to the caller's `Progress` on the walk's own
                    // tick.
                    let delivered = run.driver.delivered();
                    if delivered > run.base {
                        run.output_since_tick += delivered - run.base;
                        run.base = delivered;
                        if run.output_since_tick >= TICK {
                            run.output_since_tick = 0;
                            gate.borrow_mut().output(run.bytes + run.base)?;
                        }
                    }
                } else {
                    // A driver that decides where a member decodes needs to
                    // know whether the archive is solid, and the main
                    // header is where that is said - ahead of every member
                    // of the volume it heads.
                    run.driver.note_solid(walk.solid_archive);
                    // Once a block is finished, nothing below its end is
                    // read again: that is the drop-behind promise at every
                    // member and every block boundary (spec F 3.7.3).
                    walk.release(&gate, block.end())?;
                }
                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return Err(Error::new(ErrorKind::Cancelled).with_volume(walk.volume));
                }
            }
        })();
        // The walk's own count, carried to the next phase. What a driver
        // delivered beside the walk is its `Closed::bytes`.
        *bytes = run.bytes;
        *output_since_tick = run.output_since_tick;
        *scratch = std::mem::take(&mut run.scratch);
        *blake = run.blake.take();
        outcome
    }

    /// Retire the driver of a phase that handed off: its members settled and
    /// its closes kept for the report. A driver that hands off holds no
    /// member in flight, so its settle has nothing to close.
    #[cfg(feature = "parallel")]
    #[inline]
    pub(crate) fn retire<D: Driver>(&mut self, driver: &mut D) -> Result<()> {
        driver.settle()?;
        let closed = driver.closed();
        self.merge(closed);
        Ok(())
    }

    pub(super) fn merge(&mut self, closed: Closed) {
        let into = &mut self.closed;
        into.members += closed.members;
        into.bytes += closed.bytes;
        into.checksum_failures += closed.checksum_failures;
        into.walk_bytes_skipped += closed.walk_bytes_skipped;
        into.working_memory = into.working_memory.max(closed.working_memory);
        if into.deferred.is_none() {
            into.deferred = closed.deferred;
        }
    }

    /// End the operation under the last phase's driver: settle it, build the
    /// report, and report the first failure in archive order.
    #[inline]
    pub(crate) fn finish<D: Driver, P: Progress>(
        mut self,
        driver: &mut D,
        progress: &mut P,
        outcome: Result<()>,
    ) -> Result<ExtractReport> {
        // Every member the driver took and has not closed is closed now, in
        // archive order, whatever the walk did: a worker holding a member's
        // writer past the end of the operation is the defect of spec F 8.1
        // item 3, and a walk that failed must not be the reason a good
        // member ahead of the failure is never reported.
        let settled = driver.settle();
        let last = driver.closed();
        // A phase before this one closed its members first, so its deferred
        // error is the earlier in archive order.
        self.merge(last);
        let closed = std::mem::take(&mut self.closed);
        // The operation's own peak, which is what the report carries: the
        // walk's buffers plus the one copy buffer and the one name buffer,
        // plus whatever the driver's workers hold (API section 5.2: the
        // sequential figure times the worker count).
        let mut report = ExtractReport {
            members: closed.members,
            bytes: (self.bytes + closed.bytes).saturating_sub(closed.walk_bytes_skipped),
            checksum_failures: closed.checksum_failures,
            damaged_headers: self.walk.unsound_read(),
            peak_working_memory: 0,
        };
        report.peak_working_memory = self
            .walk
            .peak_reader_bytes
            .saturating_add(self.decoders.window_bytes())
            .saturating_add(self.scratch.held_bytes())
            .saturating_add(self.name_buf.capacity() as u64)
            .saturating_add(closed.working_memory);
        // `released` is reported on every error path before the error is
        // returned, so a caller releasing buffers is not left holding a
        // volume because extraction failed.
        let gate: Gate<'_, P> = RefCell::new(progress);
        let volume = self.walk.volume;
        let released = self.walk.released();
        let _ = gate.borrow_mut().released(volume, released);
        // SETTLED BEFORE OUTCOME, and the order is the rule of SPEC-API 8.3:
        // "the operation reports the FIRST failure in archive order".
        //
        // Every member a driver still had in flight was handed over BEFORE
        // the point the walk reached, so a fatal error from one of them is
        // earlier in archive order than anything the walk itself met.
        // Reading the walk's error first reports the later failure and
        // hides the earlier one: `f_extract_parallel` found a damaged
        // archive where the sequential path ended `LimitExceeded {
        // resource: TextModel }` on a member and the concurrent path ended
        // `Truncated` at the next header, which the walk reached because
        // the member had been dispatched.
        //
        // For the sequential driver this changes nothing: it settles
        // nothing, so `settled` is always `Ok`.
        settled?;
        outcome?;
        if let Some(err) = closed.deferred {
            return Err(err);
        }
        // Every member was delivered; a volume's locator named a quick
        // open offset its walk did not bear out (spec F 3.2.8 rule 2).
        if let Some(err) = self.walk.locator_wrong.take() {
            return Err(err);
        }
        // Every member was delivered; a later fragment's encryption
        // record was one the engine cannot use.
        if let Some(err) = self.walk.fragment_refusal.take() {
            return Err(err);
        }
        Ok(report)
    }
}

/// A member's encryption, as `member()` holds it before the decode.
pub(super) type Crypto = Option<(Option<MemberDecryptor>, Option<Rar5Keys>)>;

/// Whether the driver's small batches take THIS member, as far as its
/// disposition goes ([`batchable`] asks the rest).
#[cfg(all(feature = "parallel", not(target_arch = "x86_64")))]
#[inline(always)]
pub(super) fn batches_this<D: Driver>(driver: &D, _: &Disposition<D::Out>) -> bool {
    driver.batches_small()
}

/// Whether the driver's small batches take THIS member, as far as its
/// disposition goes ([`batchable`] asks the rest): [`batches_for`].
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
#[inline(always)]
pub(super) fn batches_this<D: Driver>(driver: &D, disposition: &Disposition<D::Out>) -> bool {
    batches_for(
        driver.batches_small(),
        driver.batches_written(),
        matches!(disposition, Disposition::Verify),
        WRITTEN_BATCHED_BY_DEFAULT,
    )
}

/// x86-64: whether the DEFAULT small batches take a written
/// member (`x`) on this operating system: on Linux only.
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
pub(super) const WRITTEN_BATCHED_BY_DEFAULT: bool = cfg!(target_os = "linux");

/// **x86-64:** at the default, the small batches take
/// a member that is VERIFIED (`t`) on every operating system, and a
/// member that is WRITTEN (`x`) only where `written_default` says so,
/// which is Linux ([`WRITTEN_BATCHED_BY_DEFAULT`]); `RARKIT_SMALL_BATCH`
/// set by name (`named`) takes both anywhere. On a Windows desktop (Zen 5)
/// batching `x` read small-r `x` 0.9665x of the control's wall, under the
/// floor, while `t` won 2.5x to 3.1x; on the Linux x86-64 VM `x` won
/// 1.34x to 1.95x (the finer x86 form).
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
#[inline(always)]
pub(super) fn batches_for(small: bool, named: bool, verify: bool, written_default: bool) -> bool {
    small && (named || verify || written_default)
}

/// Offer one member's decode to the driver (feature `parallel`).
///
/// `true` means a worker took it and the walk has already skipped its
/// packed bytes; `false` leaves the three slots exactly as they were and
/// the walk decodes the member itself.
///
/// The three are `&mut` and not values for a MEASURED reason: `Crypto`
/// carries a `MemberDecryptor`, which holds an AES key schedule, and
/// moving it in and out of this call once per member cost the 20,000
/// small-member test leg about 8% of its wall. The sequential driver
/// answers `offloads()` with a constant false and this function then
/// touches nothing at all.
#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
#[inline]
pub(super) fn offer<V: Volumes, D: Driver, P: Progress>(
    run: &mut Run<'_, D>,
    walk: &mut Walk<'_, V>,
    gate: &Gate<'_, P>,
    block: &crate::read::block::Block,
    file: &FileHdr,
    name: &[u8],
    format: Format,
    solid_archive: bool,
    solid_chain: bool,
    disposition: &mut Disposition<D::Out>,
    codec: &mut Option<Codec>,
    crypto: &mut Crypto,
) -> Result<bool> {
    if !run.driver.offloads() {
        return Ok(false);
    }
    // A stored member that starts here and continues on the next volume:
    // dispatched over its fragment list where the driver takes one.
    let split = file.split_after
        && run.driver.takes_split()
        && split_dispatchable(walk, file, block, solid_archive, codec, disposition, crypto);
    if !split
        && !dispatchable(
            walk,
            file,
            block,
            solid_archive,
            solid_chain,
            codec,
            disposition,
            batches_this(&*run.driver, disposition),
        )
    {
        return Ok(false);
    }
    let out = match std::mem::replace(disposition, Disposition::Skip) {
        Disposition::Write(w) => Out::Write(w),
        Disposition::Verify => Out::Verify,
        Disposition::Skip => unreachable!("`dispatchable` refuses a skipped member"),
    };
    let taken = codec
        .take()
        .expect("`dispatchable` refuses a refused member");
    let (decryptor, keys) = crypto.take().unwrap_or((None, None));
    let mut spare = run.driver.spare_name();
    spare.clear();
    spare.extend_from_slice(name);
    let (more, split) = if split {
        let (tx, rx) = std::sync::mpsc::channel();
        (
            Some(tx),
            Some(Split {
                checksum: crate::read::walk::fragment_crc32(file, format),
                more: rx,
            }),
        )
    } else {
        (None, None)
    };
    let job = Job {
        src: walk
            .shared_source()
            .expect("`dispatchable` refuses a walk with no volume open"),
        data: block.data.clone(),
        file: file.clone(),
        name: spare,
        format,
        out,
        codec: taken,
        decryptor,
        keys,
        volume: walk.volume,
        in_set: walk.in_set,
        split,
    };
    match run.driver.offer(job)? {
        None => {
            let mut stream = MemberStream::new(walk, gate, block, file, name);
            stream.check_leading_fragment()?;
            match more {
                // The walk crosses to each next fragment now, as it would
                // have after reading this one, and hands it on.
                Some(more) => {
                    #[cfg(feature = "test-support")]
                    crate::probe::note_split_job();
                    stream.forward_fragments(&more)?
                }
                None => stream.skip()?,
            }
            Ok(true)
        }
        // Handed back: the member is put together again exactly as it was
        // and decoded here. Every field the job took came out of one of
        // these three slots, so nothing of it is lost.
        Some(job) => {
            *disposition = match job.out {
                Out::Write(w) => Disposition::Write(w),
                Out::Verify => Disposition::Verify,
            };
            *codec = Some(job.codec);
            *crypto = Some((job.decryptor, job.keys));
            Ok(false)
        }
    }
}

/// Without the `parallel` feature there is nowhere for a decode to go, so
/// nothing is ever offered and no job is ever built.
#[cfg(not(feature = "parallel"))]
#[allow(clippy::too_many_arguments)]
#[inline]
pub(super) fn offer<V: Volumes, D: Driver, P: Progress>(
    _run: &mut Run<'_, D>,
    _walk: &mut Walk<'_, V>,
    _gate: &Gate<'_, P>,
    _block: &crate::read::block::Block,
    _file: &FileHdr,
    _name: &[u8],
    _format: Format,
    _solid_archive: bool,
    _solid_chain: bool,
    _disposition: &mut Disposition<D::Out>,
    _codec: &mut Option<Codec>,
    _crypto: &mut Crypto,
) -> Result<bool> {
    Ok(false)
}

/// Whether a member is independent of every other member of the archive.
///
/// ONE statement of it, asked by the walk before it offers a job and by the
/// driver before it decides what writer to hand back, so the two cannot
/// disagree: a driver that expected to decode a member itself and was
/// handed one to write, or the reverse, would deadlock on its own worker.
#[cfg(feature = "parallel")]
pub(crate) fn offloadable(
    solid_archive: bool,
    solid_member: bool,
    split_before: bool,
    split_after: bool,
    unpacked_size: Option<u64>,
    packed_size: u64,
    method: &Method,
) -> bool {
    !solid_archive
        && !solid_member
        && !split_before
        && !split_after
        && worth_a_worker(unpacked_size, method)
        && packed_size > 0
}

/// Whether a member is independent and SMALL: a compressed member below
/// the compressed offload floor, which the concurrent pool may take in a
/// batch with its neighbours when `RARKIT_SMALL_BATCH` says so.
///
/// The independence conditions are [`offloadable`]'s exactly. The stored
/// floor is not in the question: a small STORED member is never batched.
#[cfg(feature = "parallel")]
pub(crate) fn batchable(
    solid_archive: bool,
    solid_member: bool,
    split_before: bool,
    split_after: bool,
    unpacked_size: Option<u64>,
    packed_size: u64,
    method: &Method,
) -> bool {
    !solid_archive
        && !solid_member
        && !split_before
        && !split_after
        && matches!(method, Method::Compressed { .. })
        && unpacked_size.is_some_and(|n| n >= 1 && n < offload_floor_compressed())
        && packed_size > 0
}

/// Whether a member is big enough to pay for a worker at all.
///
/// Asked TWICE, of two different workers, and it has to be the same
/// question both times: once of the worker that would decode the member
/// whole, and once of the worker that would only WRITE it while the walk
/// decodes it. Both cost the same handoff - a channel send, a thread
/// waking, an answer coming back - and neither is worth it below the
/// floor. A member declaring no bytes is never worth one at any floor,
/// which is why the floor is taken as at least 1.
///
/// **The floor is in BYTES and the question is about TIME**, which is why
/// the method is one of the arguments: the handoff is a fixed number of
/// microseconds and what it has to be set against is how long the member
/// takes to produce, not how large it is. A stored member is produced at
/// copy speed and a compressed one at decode speed, and the two differ by
/// more than an order of magnitude ([`OFFLOAD_FLOOR_COMPRESSED`]).
#[cfg(feature = "parallel")]
pub(crate) fn worth_a_worker(unpacked_size: Option<u64>, method: &Method) -> bool {
    let floor = match method {
        Method::Stored => offload_floor(),
        Method::Compressed { .. } => offload_floor_compressed(),
    };
    unpacked_size.is_some_and(|n| n >= floor.max(1))
}

/// The smallest member worth handing to a worker, in DECLARED unpacked
/// bytes.
///
/// **MEASURED, and the measurement is the whole justification.** Handing a
/// member over costs a channel send, a worker waking, a channel receive
/// and the answer coming back, and that cost is per MEMBER and does not
/// shrink with the member. On a laptop a stored archive of 20,000
/// members of about 200 bytes each took **174 ms** through the concurrent
/// driver at width 1 against **8.4 ms** sequentially, and 72 ms at width
/// 8: about 8 us of handoff on a member whose whole decode is under half a
/// microsecond. Twenty times slower, for members the walk copies faster
/// than it can describe them to somebody else.
///
/// 256 KiB is where the handoff stops mattering. A STORED member is the
/// worst case, because it is the fastest thing the engine decodes: at the
/// 5 GB/s that laptop copies and checksums at, 256 KiB is about 50 us, so the
/// handoff is a sixth of it and eight workers still win several times
/// over. A COMPRESSED member of that size is tens of times longer again,
/// so the floor is far more conservative than that side needs.
///
/// The same floor gates the WRITE pipeline, and the measurement that made
/// that necessary is the same leg measured again: with the decode floor in
/// and the write pipeline still taking a worker per member, the 20,000
/// member leg read 117 ms against 174 ms with neither. The handoff is the
/// cost, and it does not care which half of a member's work is on the
/// other side of it.
///
/// What it costs: an archive whose members are all below the floor decodes
/// entirely on the walking thread, exactly as it did before this driver
/// existed. That is the right answer for STORED members. A COMPRESSED
/// member below [`OFFLOAD_FLOOR_COMPRESSED`] is, since 26 Sep 2026, taken
/// in a small batch instead (`batchable`, `concurrent::SMALL_BATCH_ENV`):
/// the 9,681 and 20,000 member sets it left on one core test about twice
/// as fast (the small member batches and the member team). What
/// it does NOT do is bound how wide a large archive runs.
#[cfg(feature = "parallel")]
pub(crate) const OFFLOAD_FLOOR: u64 = 256 * 1024;

/// The same question for a COMPRESSED member, and it is a different
/// number because the thing the handoff is set against is a different
/// number.
///
/// **The paragraph above says why this exists, and said so before it was
/// built**: "A COMPRESSED member of that size is tens of times longer
/// again, so the floor is far more conservative than that side needs."
/// The floor was set on a STORED member and then applied to every member,
/// which put every compressed member under 256 KiB on the walking thread
/// whatever the archive held.
///
/// **What that cost, measured (an Apple M3 Mac, 32 cores, and the reproduction
/// on a second one beside it).** A source tree of 4,017 members of 16 to 96
/// KiB at `-m3` - 230 MB unpacked in an 89.8 MB RAR 5 archive, which is
/// the ordinary shape of a user's archive and not a corner - dispatched
/// NOT ONE member: `extract_parallel` at breadth 8 ran the whole of it on
/// the walking thread, 355 ms against the old engine's 52 ms on the same
/// bytes, with rarkit's CPU seconds equal to its wall. The gate could not
/// see it because every many-member leg this harness had was STORED or
/// held members of about 200 bytes, where the floor is right.
///
/// **Why 16 KiB, and it is a SWEPT figure that overturned the argued
/// one.** This constant shipped at 32 KiB at first, on the
/// reasoning that the handoff is about 8 us, that this engine decodes
/// `-m3` text at about 650 MB/s on one core, and that 32 KiB is therefore
/// about 50 us of decode - six times the handoff, the same margin 256 KiB
/// leaves a stored member at copy speed. The sweep says that reasoning
/// prices the wrong thing. On the M3 Mac, 32 cores, over the 4,017
/// member source tree:
///
/// | floor | 8 KiB | 16 KiB | 32 KiB | 64 KiB | 128 KiB | 256 KiB |
/// |---|---|---|---|---|---|---|
/// | best wall | 59.9 ms | 59.9 ms | 100.4 ms | 203.0 ms | 306.5 ms | 306.6 ms |
///
/// **32 KiB is 1.68x the wall of 16 KiB.** What the argument left out is
/// that a member left at home is not merely a member that misses a
/// worker: it is closed through `Driver::close`, which settles and drains
/// the WHOLE flight queue because `close` is archive order. Every
/// below-floor member in a mixed archive is therefore a pipeline barrier,
/// and that cost is one-sided and much larger than the handoff the margin
/// was sized against. 32 KiB left 806 of the 4,017 members at home and so
/// bought 806 barriers; 16 KiB leaves none.
///
/// **What this table cannot say is whether a floor BELOW 16 KiB is
/// better**, because the corpus's smallest member is exactly 16 KiB: 8
/// KiB and 16 KiB are the same configuration over it and measure the same
/// to a tenth of a millisecond. 16 KiB is therefore the lowest figure the
/// table actually supports rather than extrapolates to. The naive
/// break-even - a member whose decode is shorter than the 8 us handoff is
/// cheaper at home - sits near 5 KiB at 650 MB/s, so there is room below
/// this and it needs a corpus with members in the 1 to 16 KiB range.
///
/// It is deliberately NOT derived from the declared dictionary or the
/// packed size. The dictionary says what the WRITER had, not what this
/// member costs, and a ratio is not known until the member is decoded.
#[cfg(feature = "parallel")]
pub(crate) const OFFLOAD_FLOOR_COMPRESSED: u64 = 16 * 1024;

/// The floor in force on this thread: the engine's, or a test's.
///
/// A test's figure replaces BOTH floors. A test that sets one is asking
/// for a fixture's members to be dispatched whatever they are, and every
/// fixture here is far below either floor; a sweep of the compressed
/// figure runs over a corpus that is entirely compressed, so the stored
/// floor is not in the question either way.
#[cfg(all(feature = "parallel", feature = "offload-knob"))]
pub(super) fn offload_floor() -> u64 {
    crate::probe::offload_floor().unwrap_or(OFFLOAD_FLOOR)
}

#[cfg(all(feature = "parallel", not(feature = "offload-knob")))]
pub(super) fn offload_floor() -> u64 {
    OFFLOAD_FLOOR
}

#[cfg(all(feature = "parallel", feature = "offload-knob"))]
pub(crate) fn offload_floor_compressed() -> u64 {
    crate::probe::offload_floor().unwrap_or(OFFLOAD_FLOOR_COMPRESSED)
}

#[cfg(all(feature = "parallel", not(feature = "offload-knob")))]
pub(crate) fn offload_floor_compressed() -> u64 {
    OFFLOAD_FLOOR_COMPRESSED
}

/// Whether a member's decode may leave the walking thread.
#[cfg(feature = "parallel")]
///
/// The conditions are the format's, not the implementation's, and each one
/// is a statement about what a worker would have to know that only the walk
/// knows:
///
/// - **a non-solid archive, and a member outside every solid chain.** A
///   solid member's decode begins in the window the member before it left
///   (spec F 3.6), so it is not independent of anything and the format
///   forbids running it beside its neighbour.
/// - **a member that is not split.** Spec F 3.5.4 joins a split member's
///   fragments by walking to the next volume and checking three fields
///   there; the fragments after the first are not known until that walk has
///   happened, so their ranges cannot be put in a job. A split member is
///   dispatched instead with the fragments the walk sends as it crosses to
///   them ([`split_dispatchable`]), or decoded by the walk.
/// - **a member with a codec and an output**: a refused member is reported
///   by name without being read at all, and a skipped one is never read
///   either.
/// - **a member that declares bytes.** One declaring none produces none,
///   and dispatching it would cost a job for no decode.
#[allow(clippy::too_many_arguments)]
#[inline]
pub(super) fn dispatchable<V: Volumes>(
    walk: &Walk<'_, V>,
    file: &FileHdr,
    block: &crate::read::block::Block,
    solid_archive: bool,
    solid_chain: bool,
    codec: &Option<Codec>,
    disposition: &Disposition<impl std::io::Write>,
    small: bool,
) -> bool {
    let _ = solid_chain;
    let packed = block.data.end.saturating_sub(block.data.start);
    (offloadable(
        solid_archive,
        file.solid,
        file.split_before,
        file.split_after,
        file.unpacked_size,
        packed,
        &file.method,
    ) || small
        && batchable(
            solid_archive,
            file.solid,
            file.split_before,
            file.split_after,
            file.unpacked_size,
            packed,
            &file.method,
        ))
        && codec.is_some()
        && !matches!(disposition, Disposition::Skip)
        && walk.shared_source().is_some()
}

/// Which split members the pool takes over their fragment lists: `stored`
/// for a stored, clear member only (the arrangement of 29 Sep 2026);
/// `compressed` for those and every COMPRESSED member, encrypted or not
/// (the default, [`SplitJobs::DEFAULT`]); `all` for every member whatever
/// its method and encryption. A RUNTIME knob, so one binary measures the
/// three against each other.
#[cfg(feature = "parallel")]
pub(crate) const SPLIT_JOBS_ENV: &str = "RARKIT_SPLIT_JOBS";

/// The split members the pool takes ([`SPLIT_JOBS_ENV`]).
#[cfg(feature = "parallel")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SplitJobs {
    Stored,
    Compressed,
    All,
}

#[cfg(feature = "parallel")]
impl SplitJobs {
    /// **Compressed, and not an encrypted STORED member, on its timed
    /// price** (a Zen 4 rental, a quiet box, 30 Sep 2026):
    /// S8 at `-m3 -v1g` cold `t` 2.33x and `x` 1.46x its
    /// wall under the old rule, while S8 at `-m0 -hp -v1g` cold `x` read
    /// 0.917x. An encrypted stored member keeps the sequential entry's wide
    /// read, which deciphers it across the width where a split job gives
    /// it one worker.
    pub(super) const DEFAULT: SplitJobs = SplitJobs::Compressed;
}

#[cfg(feature = "parallel")]
pub(super) fn split_jobs() -> SplitJobs {
    #[cfg(feature = "test-support")]
    if let Some(all) = crate::probe::split_jobs_all() {
        return if all {
            SplitJobs::All
        } else {
            SplitJobs::Stored
        };
    }
    static MODE: std::sync::OnceLock<SplitJobs> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        match crate::knob::reader_var(SPLIT_JOBS_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("all") => SplitJobs::All,
            Some("compressed") => SplitJobs::Compressed,
            Some("stored") => SplitJobs::Stored,
            _ => SplitJobs::DEFAULT,
        }
    })
}

/// Whether a split member of this method and encryption is taken over its
/// fragment list at all. ONE statement of it, asked by the walk
/// ([`split_dispatchable`]) and by the pool's `open` before it decides
/// whose writer the member gets, so the two cannot disagree.
///
/// **A compressed or encrypted member is as independent as a stored one.**
/// What a worker reads is the same byte stream the walk would have read:
/// the fragments' packed bytes joined in volume order (spec F 3.5.4),
/// deciphered by ONE chain across every fragment (spec K 3.6.2; the walk's
/// own stream never restarts a cipher at a fragment either). Its LZ stream
/// is serial inside the member wherever it runs; what the walk decoding it
/// cost was every OTHER member: the walk could not read the next member's
/// header until this one's last fragment was consumed, so a split set whose
/// members each straddle a volume boundary decoded one member at a time.
/// Which of them is WORTH a job is [`SplitJobs::DEFAULT`]'s measurement.
#[cfg(feature = "parallel")]
pub(crate) fn split_job_kind(stored: bool, encrypted: bool) -> bool {
    match split_jobs() {
        SplitJobs::Stored => stored && !encrypted,
        SplitJobs::Compressed => !stored || !encrypted,
        SplitJobs::All => true,
    }
}

/// Whether a member SPLIT across volumes may be dispatched over its
/// fragment list ([`Split`]): the FIRST fragment of a member outside every
/// solid chain, of a kind [`split_job_kind`] takes, large enough to be
/// worth a worker, written or verified. Every other split member is joined
/// on the walk as before.
#[cfg(feature = "parallel")]
#[inline]
pub(super) fn split_dispatchable<V: Volumes>(
    walk: &Walk<'_, V>,
    file: &FileHdr,
    block: &crate::read::block::Block,
    solid_archive: bool,
    codec: &Option<Codec>,
    disposition: &Disposition<impl std::io::Write>,
    crypto: &Crypto,
) -> bool {
    let packed = block.data.end.saturating_sub(block.data.start);
    !file.split_before
        && file.split_after
        && codec.is_some()
        && split_job_kind(
            matches!(codec, Some(Codec::Stored)),
            crypto.as_ref().is_some_and(|(cipher, _)| cipher.is_some()),
        )
        && offloadable(
            solid_archive,
            file.solid,
            false,
            false,
            file.unpacked_size,
            packed,
            &file.method,
        )
        && !matches!(disposition, Disposition::Skip)
        && walk.shared_source().is_some()
}
