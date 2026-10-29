//! The chain finders over a span: the chains planned, built and walked,
//! and the sliding wave.

use super::*;

impl Engine {
    /// Where a parse worker hands a whole small member's tokens, when the
    /// flush writes it by the carried-set chains: the flush's direct buffers
    /// and the segment. `None` for a segment written as it is parsed.
    pub(super) fn chain_slot<'d>(
        &self,
        direct: &'d Direct,
        segment: usize,
    ) -> Option<(&'d Direct, usize)> {
        self.defers
            .get(segment)
            .copied()
            .unwrap_or(false)
            .then_some((direct, segment))
    }

    /// The stride the pass links block `job` at: this engine's empty
    /// stride ([`EMPTY_STRIDE`]) where the chains are keyed on four bytes
    /// and the block's own effort ([`Engine::effort_for`]) is the floor
    /// scan; else 1. A function of the block's bytes and the plan alone,
    /// never of the width.
    ///
    /// The block's own effort, not the level's plan: the floor plan (the
    /// store rule's sampler) and a lone member's floor parse lazily over
    /// these chains, and a lazy parse wants every position linked.
    pub(super) fn link_stride(&self, links: &Links, slice: &[u8], job: &Job) -> usize {
        if self.empty_stride == 1 || links.key() != KEY_SHORT {
            return 1;
        }
        let block = Block {
            span: slice,
            start: job.bytes.start,
            end: job.bytes.end,
            dictionary: links.reach(),
        };
        if self.effort_for(block, !job.records.is_empty()).parse == Parse::Scan {
            self.empty_stride
        } else {
            1
        }
    }

    /// Link block `job` of `slice`, at its [`Engine::link_stride`].
    pub(super) fn link_block(&self, links: &Links, heads: &mut [u32], slice: &[u8], job: &Job) {
        match self.link_stride(links, slice, job) {
            1 => links.insert(heads, slice, job.bytes.clone()),
            stride => links.insert_sparse(heads, slice, job.bytes.clone(), stride),
        }
    }

    /// Lay out the flush's chains (spec H3 section 4) before
    /// any member is parsed.
    ///
    /// **The members that open a set are fixed before any is written.**
    /// A chain of members shares one set's lifetime from a FORCED opener:
    /// the first whole small member after anything else (a run's start, a
    /// member of [`CARRY_MEMBER_BYTES`] or more, a window of a larger
    /// one), and every [`CARRY_MEMBERS_MOST`]th member after the last
    /// forced one. Inside a chain a member may still open a set of its own
    /// where that is smaller (the format's choice, from its own tokens and
    /// the carried set), which only makes the envelope's gap shorter, so
    /// it moves no forced opener. The forced openers are a function of the
    /// members' order and sizes alone, never of how the run was cut into
    /// batches or of the thread count, and chains share nothing but the
    /// WINDOW (the counts of the members before a forced opener), which
    /// is taken in member order: so the bytes are the same at any width
    /// and any batching (API promise 6).
    ///
    /// **A chain is written as soon as its members are parsed**, by the
    /// worker that parsed the last of them ([`Engine::member_parsed`]),
    /// while the parse goes on; the chains are TAKEN one after another in
    /// member order, which is what the window needs, and written in
    /// parallel.
    pub(super) fn plan_chains(&mut self) {
        let mut chains: Vec<ChainPlan> = Vec::new();
        let mut chain_of = vec![None; self.defers.len()];
        let mut carried = self.carry.take();
        let mut members = self.carry_members;
        let mut open: Option<ChainPlan> = None;
        let mut gap = false;
        for (index, &defers) in self.defers.iter().enumerate() {
            if !defers {
                // Not a whole small member: it writes its own sets, and the
                // one it leaves is not known here.
                chains.extend(open.take());
                carried = None;
                members = 0;
                gap = true;
                continue;
            }
            let forced = carried.is_none() || members >= CARRY_MEMBERS_MOST;
            if forced {
                chains.extend(open.take());
                open = Some(ChainPlan {
                    start: index,
                    end: index + 1,
                    carried: None,
                    members: 0,
                    clear_window: gap,
                });
                carried = Some(CarriedSet::default());
                members = 1;
            } else {
                match &mut open {
                    Some(chain) => chain.end = index + 1,
                    None => {
                        open = Some(ChainPlan {
                            start: index,
                            end: index + 1,
                            carried: carried.take(),
                            members,
                            clear_window: gap,
                        });
                        carried = Some(CarriedSet::default());
                    }
                }
                members += 1;
            }
            gap = false;
        }
        chains.extend(open.take());
        for (number, chain) in chains.iter().enumerate() {
            for slot in &mut chain_of[chain.start..chain.end] {
                *slot = Some(number);
            }
        }
        let trailing = self.defers.last().copied().unwrap_or(false);
        let any = !chains.is_empty();
        self.chain_missing.clear();
        self.chain_missing.extend(
            chains
                .iter()
                .map(|chain| AtomicUsize::new(chain.end - chain.start)),
        );
        if self.chain_cells.len() < self.defers.len() {
            self.chain_cells
                .resize_with(self.defers.len(), || Mutex::new(None));
        }
        self.chain_of = chain_of;
        let work = ChainWork {
            chains,
            next: 0,
            window: std::mem::take(&mut self.carry_window),
            window_on: self.carry_window_on,
            lookahead: self.carry_lookahead,
            end: None,
            trailing,
            gap_after: !trailing,
        };
        if !any {
            // Nothing here carries: whatever this flush writes, no set it
            // leaves is known here, so the next member opens one.
            if !self.defers.is_empty() {
                self.carry_members = 0;
                self.carry_window.clear();
            }
            *self.chain_work.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return;
        }
        *self.chain_work.lock().unwrap_or_else(|e| e.into_inner()) = Some(work);
    }

    /// Member `segment` is parsed: hand it to its chain, and write every
    /// chain whose members are now all parsed, in member order, into the
    /// flush's direct buffers (`direct`), or where there are none (the
    /// empty members a flush registers before its parse) leave them for
    /// [`Engine::finish_chains`].
    pub(super) fn member_parsed<F: Emit>(
        &self,
        format: &F,
        segment: usize,
        member: Deferred,
        direct: Option<&Direct>,
    ) {
        *self.chain_cells[segment]
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(member);
        let chain = self.chain_of[segment].expect("a deferred member is in a chain");
        let complete = self.chain_missing[chain].fetch_sub(1, Ordering::AcqRel) == 1;
        let Some(direct) = direct.filter(|_| complete) else {
            return;
        };
        let taken = {
            let mut guard = self.chain_work.lock().unwrap_or_else(|e| e.into_inner());
            let work = guard.as_mut().expect("a chain plan for a deferred member");
            work.take_ready(&self.chain_cells, &self.chain_missing)
        };
        let write = |job: ChainJob| {
            let chain = job.chain;
            let end = job.write(format, &mut |segment, write| {
                let slot = direct
                    .get(segment)
                    .expect("a deferred member has its buffer");
                write(&mut slot.lock().unwrap_or_else(|e| e.into_inner()));
            });
            self.chain_ended(chain, end);
        };
        // The chains one parse makes ready are written at once: the parse
        // that finishes a batch can free every chain behind it.
        #[cfg(feature = "parallel")]
        if taken.len() > 1 {
            use rayon::prelude::*;
            taken.into_par_iter().for_each(write);
            return;
        }
        taken.into_iter().for_each(write);
    }

    /// Record the set in force after chain `chain`, where it is the
    /// flush's last chain and ends the flush.
    pub(super) fn chain_ended(&self, chain: usize, end: (Option<CarriedSet>, usize)) {
        let mut guard = self.chain_work.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(work) = guard.as_mut() {
            if chain + 1 == work.chains.len() {
                work.end = Some(end);
            }
        }
    }

    /// Write whatever chains the parse did not (every chain, in a flush
    /// with nothing to parse), then leave the set in force, the members
    /// on it and the window for the next flush.
    pub(super) fn finish_chains<F: Emit>(&mut self, format: &F, outs: &mut [Vec<u8>]) {
        let Some(mut work) = self
            .chain_work
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            self.defers.clear();
            return;
        };
        for job in work.take_ready(&self.chain_cells, &self.chain_missing) {
            let chain = job.chain;
            let end = job.write(format, &mut |segment, write| write(&mut outs[segment]));
            if chain + 1 == work.chains.len() {
                work.end = Some(end);
            }
        }
        debug_assert_eq!(work.next, work.chains.len(), "every chain written");
        match (work.trailing, work.end.take()) {
            (true, Some((carried, members))) if carried.is_some() => {
                self.carry = carried;
                self.carry_members = members;
            }
            _ => {
                self.carry = None;
                self.carry_members = 0;
            }
        }
        self.carry_window = std::mem::take(&mut work.window);
        if work.gap_after {
            self.carry_window.clear();
        }
        self.defers.clear();
    }

    /// The chains, as the same pipeline: the inserting pass links a block
    /// and a parse of it starts on another thread while the pass goes on
    /// to the next. The links are shared between the two sides and `chain`
    /// says why that cannot move a byte; the heads are the pass's alone.
    /// How many blocks make a wave is what the cyclic buffer can hold ahead
    /// of the slowest parse, and it moves no byte of output either.
    ///
    /// The wave runs over the whole BATCH here too. The pass links each
    /// block over its own member's slice, so a member's last three
    /// positions are linked exactly as they were when the member was the
    /// last thing in the buffer, which is to say not at all.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_chains<F: Emit>(
        &self,
        format: &F,
        span: &[u8],
        region: Region,
        segments: &[Segment],
        jobs: &[Job],
        records: &[BlockRecord],
        chains: &mut Chains,
        outs: &mut [Vec<u8>],
    ) {
        let blocks = jobs.len();
        // Held where the writer holds it ([`Engine::hold_chain_width`];
        // `usize::MAX` otherwise, and the width is the wave's): a narrower
        // wave is fewer blocks in flight and the same bytes.
        let width = (chains.wave_bytes(span.len()) / PARSE_BLOCK_BYTES)
            .clamp(1, blocks)
            .min(self.chain_width);
        // The plan's far-link budget, or none, for every search of this
        // flush: the level's, a lone member's and an empty block's alike,
        // which are one plan's efforts and carry the one budget.
        chains.links.set_far_budget(self.plan.far_links);
        let (heads, links) = (&mut chains.heads, &chains.links);
        let direct = Direct::new(outs, jobs);
        // The pass built across the pool, where the wave is wide enough
        // and the pool too ([`Engine::chain_builders`]): the links are
        // the pass's all the same (`chain`'s notes).
        let builders = self.chain_builders(width);
        #[cfg(feature = "parallel")]
        let mut build = self.build.lock().unwrap_or_else(|e| e.into_inner());
        // The history this call has not already linked, linked but never
        // parsed: `with_tree` says why, and why a carried index skips it.
        // Where the pass is built across the pool, it is the first wave's
        // first pieces.
        let first_start = segments[0].start;
        #[cfg(feature = "parallel")]
        let mut history: Vec<Piece> = Vec::new();
        if region.indexed < first_start {
            #[cfg(feature = "parallel")]
            if builders > 1 {
                let cut = segments[0].end;
                let mut at = region.indexed;
                while at < first_start {
                    let end = (at + PIECE_MOST).min(first_start);
                    history.push(Piece {
                        cut,
                        range: at..end,
                        parses: 0..0,
                        stride: 1,
                    });
                    at = end;
                }
            }
            if builders == 1 {
                links.insert(heads, &span[..segments[0].end], region.indexed..first_start);
            }
        }
        let parse = |index: usize| -> Vec<u8> {
            let job = &jobs[index];
            let block = Block {
                span: slice_of(span, segments, job),
                start: job.bytes.start,
                end: job.bytes.end,
                dictionary: links.reach(),
            };
            let effort = self.effort_for(block, !job.records.is_empty());
            let source = Source::Chains {
                chains: links,
                depth: effort.depth,
                enough: effort.enough,
                pair: effort.pair,
            };
            self.encode_block(
                format,
                block,
                source,
                job.last,
                effort,
                &records[job.records.clone()],
                direct.get(job.out),
                self.chain_slot(&direct, job.segment),
            )
        };
        // More than one wave: the waves slide rather than end on their
        // slowest block.
        #[cfg(feature = "parallel")]
        if blocks > width && self.slides() {
            let pass = Pass {
                heads,
                links,
                builders,
                build: &mut build,
                history: std::mem::take(&mut history),
            };
            self.chains_sliding(span, segments, jobs, width, pass, &parse, outs);
            direct.restore(outs);
            return;
        }
        let mut first = 0;
        while first < blocks {
            let wave = first..(first + width).min(blocks);
            let packed: Vec<OnceLock<Vec<u8>>> = wave.clone().map(|_| OnceLock::new()).collect();
            let parse = |index: usize| {
                packed[index - wave.start]
                    .set(parse(index))
                    .expect("one parse per block");
            };
            // One block has nothing to overlap: see `with_tree`.
            #[cfg(feature = "parallel")]
            if wave.len() > 1 && builders > 1 {
                let mut pieces = std::mem::take(&mut history);
                let stride = |index: usize| {
                    self.link_stride(links, slice_of(span, segments, &jobs[index]), &jobs[index])
                };
                pieces_of(jobs, segments, wave.clone(), &stride, &mut pieces);
                let parse = &parse;
                rayon::in_place_scope(|scope| {
                    let ready = |index: usize| scope.spawn(move |_| parse(index));
                    build.run(heads, links, span, &pieces, builders, &ready);
                });
            } else if wave.len() > 1 {
                rayon::scope(|scope| {
                    for index in wave.clone() {
                        self.link_block(
                            links,
                            heads,
                            slice_of(span, segments, &jobs[index]),
                            &jobs[index],
                        );
                        let parse = &parse;
                        scope.spawn(move |_| parse(index));
                    }
                });
            }
            #[cfg(feature = "parallel")]
            let serial = wave.len() == 1;
            #[cfg(not(feature = "parallel"))]
            let serial = true;
            if serial {
                for index in wave.clone() {
                    self.link_block(
                        links,
                        heads,
                        slice_of(span, segments, &jobs[index]),
                        &jobs[index],
                    );
                    parse(index);
                }
            }
            let mut spare = self.spare_outs.lock().unwrap_or_else(|e| e.into_inner());
            for (index, bytes) in wave.clone().zip(packed) {
                let bytes = bytes.into_inner().expect("every block was parsed");
                outs[jobs[index].out].extend_from_slice(&bytes);
                keep_out(&mut spare, bytes);
            }
            drop(spare);
            first = wave.end;
        }
        direct.restore(outs);
    }

    /// [`Engine::with_chains`]'s waves, SLIDING: the pass links block `j`
    /// as soon as every block up to `j - width` has been parsed, rather
    /// than when all of a wave of `width` blocks has. The outputs are
    /// appended to their members in block order as the parsed prefix
    /// grows.
    ///
    /// **Why.** A wave ended when its slowest block did, and every other
    /// thread waited for it: on bin4g at `-m3` on 32 cores the process was
    /// at most eight threads wide for about half its wall
    /// (measured 30 Sep 2026). Sliding, the next wave's blocks start while this one's last
    /// parses finish, and a flush waits on its slowest block once, at its
    /// end.
    ///
    /// **Why it moves no byte.** `chain` says what the links owe a parse:
    /// a block is linked whole before its parse starts, and the pass is
    /// never more than [`Chains::wave_bytes`] ahead of the start of any
    /// block still being parsed. The pass links the same positions in the
    /// same order over the same slices as the waves did; `width` blocks
    /// of at most [`PARSE_BLOCK_BYTES`] each are at most `wave_bytes`, and
    /// no block is linked until the block `width` before it is done, so
    /// the oldest block in flight starts no more than that behind the end
    /// of the newest. A parse reads its own block, the links and nothing
    /// another parse writes.
    ///
    /// **What it holds.** At most `width` blocks are parsed or waiting to
    /// be appended at once, which is what one wave held
    /// ([`Engine::flight_term`]); the pass's lead is the same bound.
    ///
    /// **Who waits.** The pool thread the scope's body runs on, which runs
    /// the pass; a caller that is not a pool thread only waits for the
    /// scope, as it waited for a wave's. While the pass waits for a block it runs a queued parse itself
    /// only where there are at least as many queued as the pool has
    /// threads, so its turn at a parse leaves the others a round of work;
    /// otherwise it sleeps until a parse ends, and costs no CPU. Beside
    /// another pass it never sleeps for good on a queued parse ([`Sliding`]
    /// says why that is not a choice).
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn chains_sliding(
        &self,
        span: &[u8],
        segments: &[Segment],
        jobs: &[Job],
        width: usize,
        pass: Pass<'_>,
        parse: &(dyn Fn(usize) -> Vec<u8> + Sync),
        outs: &mut [Vec<u8>],
    ) {
        #[cfg(any(test, feature = "bench-internals"))]
        SLID_FLUSHES.fetch_add(1, Ordering::Relaxed);
        let Pass {
            heads,
            links,
            builders,
            build,
            mut history,
        } = pass;
        let blocks = jobs.len();
        // Built across the pool, the pass links a quarter of a wave at a
        // call: the build's own width is in the call, and the window
        // stays at least three quarters full while the next quarter is
        // linked. On one thread it links a block at a time.
        let step = if builders > 1 { (width / 4).max(1) } else { 1 };
        let packed: Vec<Mutex<Vec<u8>>> = (0..blocks).map(|_| Mutex::new(Vec::new())).collect();
        let finished: Vec<AtomicUsize> = (0..blocks).map(|_| AtomicUsize::new(0)).collect();
        let started = AtomicUsize::new(0);
        // The thread that runs the pass: `rayon::scope` runs its body on a
        // pool thread whichever thread calls it (the command line's own
        // thread, at the pool's full width), so it is taken there.
        let driver: OnceLock<std::thread::Thread> = OnceLock::new();
        let threads = threads();
        let run = |index: usize| {
            // Counted done when it ends, however it ends: a parse that
            // panicked leaves the driver waiting on no one, and the scope
            // raises the panic when it closes.
            let _done = Finished(&finished[index], driver.get());
            started.fetch_add(1, Ordering::Relaxed);
            *packed[index].lock().unwrap_or_else(|e| e.into_inner()) = parse(index);
        };
        let _sliding = Sliding::enter();
        let wait = |index: usize, spawned: usize| {
            while finished[index].load(Ordering::Acquire) == 0 {
                // Alone on the pool, a pool's worth queued before the
                // driver takes one. Beside other engines (the ones the
                // writer said share the pool, [`Engine::share_pool`], or
                // the passes in flight anywhere in the process,
                // [`Sliding`], read each time round since a second write
                // may start at any moment) it takes one as soon as more
                // are queued than its SHARE of the pool's threads could be
                // running, which is any at all where there are as many
                // engines as threads.
                let sharers = self.shares_pool.max(Sliding::now());
                let shared = sharers > 1;
                let helps_from = if shared {
                    (threads / sharers).max(1)
                } else {
                    threads
                };
                let queued = spawned.saturating_sub(started.load(Ordering::Relaxed));
                if queued >= helps_from && rayon::yield_now() == Some(rayon::Yield::Executed) {
                    continue;
                }
                // Under its share, a sharing pass gives the pool's free
                // threads a moment to take what is queued, since every
                // parse it runs itself is the linking pass standing still;
                // and then takes one, because the threads it counted as
                // free may all be another engine's or a crew's, and a pass
                // that slept on them would wait for one to end its job.
                if shared && queued > 0 {
                    std::thread::park_timeout(SHARED_PATIENCE);
                    if finished[index].load(Ordering::Acquire) == 0
                        && spawned > started.load(Ordering::Relaxed)
                    {
                        let _ = rayon::yield_now();
                    }
                    continue;
                }
                // A parse that ends after the load above unparks this
                // thread, and `park` returns at once for an unpark that
                // came first, so no end is missed; a spurious return only
                // loads again.
                std::thread::park();
            }
        };
        // Block `index`'s output to its member, and its buffer back to be
        // handed out again, as a wave's are.
        let append = |index: usize, outs: &mut [Vec<u8>]| {
            let bytes =
                std::mem::take(&mut *packed[index].lock().unwrap_or_else(|e| e.into_inner()));
            outs[jobs[index].out].extend_from_slice(&bytes);
            keep_out(
                &mut self.spare_outs.lock().unwrap_or_else(|e| e.into_inner()),
                bytes,
            );
        };
        let mut appended = 0;
        rayon::scope(|scope| {
            driver.get_or_init(std::thread::current);
            let mut next = 0;
            while next < blocks {
                let end = (next + step).min(blocks);
                while end > appended + width {
                    wait(appended, next);
                    append(appended, outs);
                    appended += 1;
                }
                debug_assert!(
                    jobs[end - 1].bytes.end - jobs[appended].bytes.start
                        <= width * PARSE_BLOCK_BYTES,
                    "the pass runs at most a wave ahead of the oldest parse"
                );
                if builders > 1 {
                    // The history's pieces, where this call has any, go
                    // first, as they do in the first wave's build.
                    let mut pieces = std::mem::take(&mut history);
                    let stride = |index: usize| {
                        self.link_stride(
                            links,
                            slice_of(span, segments, &jobs[index]),
                            &jobs[index],
                        )
                    };
                    pieces_of(jobs, segments, next..end, &stride, &mut pieces);
                    let run = &run;
                    let ready = |index: usize| scope.spawn(move |_| run(index));
                    build.run(heads, links, span, &pieces, builders, &ready);
                } else {
                    self.link_block(
                        links,
                        heads,
                        slice_of(span, segments, &jobs[next]),
                        &jobs[next],
                    );
                    let run = &run;
                    scope.spawn(move |_| run(next));
                }
                next = end;
            }
        });
        for index in appended..blocks {
            append(index, outs);
        }
    }
}

/// The chains' build's pieces for the blocks of `wave`, after `pieces`:
/// a segment's consecutive blocks, as many as a [`Piece`] holds, with
/// the wave's first block a piece of its own so that its parse starts
/// as soon as one block is linked, and a block whose link stride
/// (`stride`, [`Engine::link_stride`]) differs from the one before it
/// starting a piece. How the blocks are cut into pieces moves no link
/// (`chain`'s notes, `chain::empty_takes`).
#[cfg(feature = "parallel")]
pub(super) fn pieces_of(
    jobs: &[Job],
    segments: &[Segment],
    wave: Range<usize>,
    stride: &dyn Fn(usize) -> usize,
    pieces: &mut Vec<Piece>,
) {
    let strides: Vec<usize> = wave.clone().map(stride).collect();
    let stride_of = |index: usize| strides[index - wave.start];
    let mut at = wave.start;
    while at < wave.end {
        let segment = jobs[at].segment;
        let start = jobs[at].bytes.start;
        let step = stride_of(at);
        let mut end = at + 1;
        while at > wave.start
            && end < wave.end
            && jobs[end].segment == segment
            && jobs[end].bytes.end - start <= PIECE_MOST
            && stride_of(end) == step
        {
            debug_assert_eq!(jobs[end].bytes.start, jobs[end - 1].bytes.end);
            end += 1;
        }
        pieces.push(Piece {
            cut: segments[segment].end,
            range: start..jobs[end - 1].bytes.end,
            parses: at..end,
            stride: step,
        });
        at = end;
    }
}

/// How many sliding passes ([`Engine::chains_sliding`]) are in flight in
/// this process, and the guard that counts one.
///
/// **Why it is counted.** A pass that waits for a block sleeps unless a
/// pool's worth of parses are queued, which is right alone on its pool:
/// another thread takes the parse. Where every thread of a pool is such a
/// pass, each sleeps on a parse only a pool thread can run and none is
/// awake, for good: two writes at once on a pool of two, which a library
/// caller reaches from two of its own threads since a write's pool is
/// shared by every write of its width (`write::width`), and a team of as
/// many engines as the pool has threads. `tests/shared_pool_drivers.rs`
/// holds both under a bounded wait. So a pass that is not the only one
/// never sleeps on a queued parse for good: it runs one itself as soon as
/// more are queued than its share of the pool's threads could be running
/// (any at all where the passes are as many as the threads), and after a
/// short patience otherwise ([`SHARED_PATIENCE`]).
///
/// **Why a process-wide count and not a pool's.** rayon does not say
/// which pool's threads are idle, and the count errs one way only: two
/// passes on two different pools each take a parse a sleeping thread
/// would have, which costs a little of the pass's lead and no byte. A
/// pass that read "alone" just before a second began sleeps on at most
/// one flush of the second's, which never sleeps on a queued parse and
/// whose thread takes the first's when its flush ends.
#[cfg(feature = "parallel")]
pub(super) struct Sliding;

/// How long a sliding pass that shares its pool waits for a free thread to
/// take a queued parse before it runs one itself (`Engine::chains_sliding`):
/// a tenth of what a parse block takes at the fastest level, so a pass that
/// has no free thread to wait for loses little, and one that has does not
/// stand still for a block. It orders work between threads and reaches no
/// byte and no choice.
#[cfg(feature = "parallel")]
pub(super) const SHARED_PATIENCE: std::time::Duration = std::time::Duration::from_micros(300);

#[cfg(feature = "parallel")]
pub(super) static SLIDING_NOW: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "parallel")]
impl Sliding {
    pub(super) fn enter() -> Sliding {
        SLIDING_NOW.fetch_add(1, Ordering::AcqRel);
        Sliding
    }

    /// How many passes are in flight, the caller's own among them.
    pub(super) fn now() -> usize {
        SLIDING_NOW.load(Ordering::Acquire)
    }
}

#[cfg(feature = "parallel")]
impl Drop for Sliding {
    fn drop(&mut self) {
        SLIDING_NOW.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Marks its block parsed when dropped, and wakes the thread that drives
/// the pass (`Engine::chains_sliding`), in that order.
#[cfg(feature = "parallel")]
pub(super) struct Finished<'a>(&'a AtomicUsize, Option<&'a std::thread::Thread>);

#[cfg(feature = "parallel")]
impl Drop for Finished<'_> {
    fn drop(&mut self) {
        self.0.store(1, Ordering::Release);
        if let Some(driver) = self.1 {
            driver.unpark();
        }
    }
}
