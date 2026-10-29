//! The tree walk over a span: one walker, or walkers overlapped.

use super::*;

impl Engine {
    /// The tree's walk and the parses, as a pipeline: a block is parsed on
    /// another thread as soon as its hints exist, while the walk goes on
    /// to the block after it. The hint buffer holds `width` blocks, so
    /// that many are in flight at once; it moves no byte of output.
    ///
    /// The wave runs over the whole BATCH and stops at no member
    /// boundary, which is the point of staging one. Nothing the tree
    /// gives a block depends on how wide the wave was: the parse of a
    /// tree block reads its own hints and never the tree, so the walk
    /// running ahead of it cannot be seen, and the walk's own answers are
    /// the serial walk's at any walker count and any chunking (the tree's
    /// own documentation says why, and passes the comparison limit apart
    /// from the chunk for exactly that reason).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_tree<F: Emit>(
        &self,
        format: &F,
        span: &[u8],
        region: Region,
        segments: &[Segment],
        jobs: &[Job],
        records: &[BlockRecord],
        width: usize,
        tree: &mut BucketTrees,
        outs: &mut [Vec<u8>],
    ) {
        let stride = self.plan.candidates;
        let walkers = self.walkers();
        // The width this walk settled on, for the test that shows
        // `WriteOptions::workers` reaches here at all. Compiled out
        // entirely without `test-support`; see `crate::probe`.
        #[cfg(feature = "test-support")]
        crate::probe::note_walkers(walkers);
        let reach = tree.window().min(self.dictionary);
        // What history this call has not already walked is walked first
        // and keeps no hints: nothing is parsed over it, and what it is
        // there for is that a position after it can descend to a match
        // inside it. A CARRIED index has walked all of it already and
        // this is a no-op, which is what makes a solid set cheap.
        let first_start = segments[0].start;
        if region.indexed < first_start {
            tree.advance_range(
                &span[..segments[0].end],
                region.indexed..first_start,
                None,
                stride,
                walkers,
            );
        }
        // A wave holds whole walk GROUPS (`group_end`), as many as the
        // hint buffer's `width` blocks of positions take, at least one.
        // Whole groups, because a group's end is its positions' comparison
        // limit (`BucketTrees::advance_range`) and so part of the
        // answer: a wave that ended inside one would walk it as two, and
        // the bytes would turn on how wide the wave was. The hints are
        // packed by POSITION, so a wave of small members holds as many of
        // them as it holds bytes of one large one.
        let capacity = width * PARSE_BLOCK_BYTES;
        #[cfg(feature = "parallel")]
        if self.parses == usize::MAX
            && width >= 2 * WALK_BLOCKS
            && threads() > 1
            && self.with_tree_overlapped(
                format,
                span,
                segments,
                jobs,
                records,
                capacity / 2,
                walkers,
                reach,
                tree,
                outs,
            )
        {
            return;
        }
        let direct = Direct::new(outs, jobs);
        let mut first = 0;
        while first < jobs.len() {
            let origin = jobs[first].bytes.start;
            let mut end = group_end(jobs, first);
            while end < jobs.len() {
                let next = group_end(jobs, end);
                if jobs[next - 1].bytes.end - origin > capacity {
                    break;
                }
                end = next;
            }
            let wave = first..end;
            let packed: Vec<OnceLock<Vec<u8>>> = wave.clone().map(|_| OnceLock::new()).collect();
            let slots_of = |index: usize| {
                let at = (jobs[index].bytes.start - origin) * stride;
                &self.hints[at..at + jobs[index].bytes.len() * stride]
            };
            let parse = |index: usize| {
                let job = &jobs[index];
                let block = Block {
                    span: slice_of(span, segments, job),
                    start: job.bytes.start,
                    end: job.bytes.end,
                    dictionary: reach,
                };
                // The hints are already walked, so a tree level's floor
                // drops the DELIBERATION and not a search: the walk has
                // to take every position either way.
                let effort = self.effort_for(block, !job.records.is_empty());
                let source = Source::Hints {
                    slots: slots_of(index),
                    stride,
                };
                let bytes = self.encode_block(
                    format,
                    block,
                    source,
                    job.last,
                    effort,
                    &records[job.records.clone()],
                    direct.get(job.out),
                    self.chain_slot(&direct, job.segment),
                );
                packed[index - wave.start]
                    .set(bytes)
                    .expect("one parse per block");
            };
            // One PASS of the walk: the groups from `at`, as many as
            // [`WALK_BLOCKS`] blocks' bytes take, at least one, dealt to
            // the walkers together, each group's positions compared up to
            // that group's own end (`BucketTrees::advance_ranges`), so
            // the answers are the ones a call a group gave. A large
            // member's group is a pass of its own; a solid set's small
            // members are each a group far shorter than a deal is worth,
            // and a pass of them is as wide as one of a large member.
            let mut ends = Vec::new();
            let pass_end = |at: usize, ends: &mut Vec<usize>| {
                ends.clear();
                let origin = jobs[at].bytes.start;
                let mut to = group_end(jobs, at);
                ends.push(jobs[to - 1].bytes.end);
                while to < wave.end {
                    let next = group_end(jobs, to);
                    if jobs[next - 1].bytes.end - origin > WALK_BLOCKS * PARSE_BLOCK_BYTES {
                        break;
                    }
                    ends.push(jobs[next - 1].bytes.end);
                    to = next;
                }
                to
            };
            let mut walk = |pass: Range<usize>, ends: &[usize]| {
                let from = (jobs[pass.start].bytes.start - origin) * stride;
                let bytes = jobs[pass.start].bytes.start..jobs[pass.end - 1].bytes.end;
                let slots = &self.hints[from..from + bytes.len() * stride];
                // The walk writes every slot of every position it visits,
                // which is all of them but the span's last three: those,
                // and only those, are cleared here. Clearing the whole pass
                // first was 16 bytes a position of stores on this thread,
                // the walk's critical path, before any walker could start.
                let unvisited = span.len().saturating_sub(3).max(bytes.start);
                if bytes.end > unvisited {
                    for slot in &slots[(unvisited - bytes.start) * stride..] {
                        slot.store(0, Ordering::Relaxed);
                    }
                }
                // A short pass is walked by this thread alone: dealing a
                // few KiB into bins and waking walkers for them cost more
                // than the walk, and the answers are the same at any
                // walker count.
                let width = if bytes.len() < WALK_ALONE_BYTES {
                    1
                } else {
                    walkers
                };
                tree.advance_ranges(span, bytes.start, ends, Some(slots), stride, width);
            };
            // A wave of ONE block has nothing to overlap, and handing its
            // parse to another thread only to wait for it cost a small
            // member more than the parse did (a non-solid set of small
            // members is one such wave per member). It runs here instead,
            // which is the serial arm below and the same bytes.
            #[cfg(feature = "parallel")]
            if wave.len() > 1 && self.parses >= wave.len() {
                rayon::scope(|scope| {
                    let mut at = wave.start;
                    while at < wave.end {
                        let pass = at..pass_end(at, &mut ends);
                        walk(pass.clone(), &ends);
                        at = pass.end;
                        for index in pass {
                            let parse = &parse;
                            scope.spawn(move |_| parse(index));
                        }
                    }
                });
            } else if wave.len() > 1 {
                // Held to `self.parses` at once (`Engine::hold_parses`):
                // the walk queues each pass's blocks, and at most that
                // many LANES take them in order, a lane ending when it
                // finds the queue empty. Queue and count share one lock,
                // so a pass queued after a lane found nothing starts a
                // lane of its own. Nothing waits; the bytes are the
                // spawned arm's, since which thread parses a block and
                // when moves none of them.
                let lanes = Mutex::new((std::collections::VecDeque::new(), 0usize));
                let lane = || loop {
                    let next = {
                        let mut state = lanes.lock().unwrap_or_else(|e| e.into_inner());
                        match state.0.pop_front() {
                            Some(index) => index,
                            None => {
                                state.1 -= 1;
                                return;
                            }
                        }
                    };
                    parse(next);
                };
                rayon::scope(|scope| {
                    let mut at = wave.start;
                    while at < wave.end {
                        let pass = at..pass_end(at, &mut ends);
                        walk(pass.clone(), &ends);
                        at = pass.end;
                        let mut state = lanes.lock().unwrap_or_else(|e| e.into_inner());
                        state.0.extend(pass);
                        while state.1 < self.parses && !state.0.is_empty() {
                            state.1 += 1;
                            let lane = &lane;
                            scope.spawn(move |_| lane());
                        }
                    }
                });
            }
            #[cfg(feature = "parallel")]
            let serial = wave.len() == 1;
            #[cfg(not(feature = "parallel"))]
            let serial = true;
            if serial {
                let mut at = wave.start;
                while at < wave.end {
                    let pass = at..pass_end(at, &mut ends);
                    walk(pass.clone(), &ends);
                    at = pass.end;
                    pass.for_each(&parse);
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

    /// `with_tree`'s waves OVERLAPPED: the hint buffer is two halves, a
    /// wave of whole groups fills one, and the next wave is walked into
    /// the other while the first's last parses finish. A half is walked
    /// into again only once every parse of the wave before in it is done,
    /// and that wave's outputs are appended then, in order.
    ///
    /// Measured on an Apple M3 Mac (untimed, tree5k at -m5 -s): the flush waited
    /// at the end of every wave for its last parses, 0.27 to 0.31 s of a
    /// 2.3 s wall with 34 waves in 18 flushes; the waits between two waves
    /// of one flush are what this takes away. Nothing a block's parse or
    /// the walk reads depends on which half a wave's hints sit in, so no
    /// byte moves: the waves are whole groups, as `with_tree`'s are.
    ///
    /// Answers whether it walked the flush: a flush of one wave is
    /// `with_tree`'s own loop, and it declines.
    #[cfg(feature = "parallel")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_tree_overlapped<F: Emit>(
        &self,
        format: &F,
        span: &[u8],
        segments: &[Segment],
        jobs: &[Job],
        records: &[BlockRecord],
        half: usize,
        walkers: usize,
        reach: usize,
        tree: &mut BucketTrees,
        outs: &mut [Vec<u8>],
    ) -> bool {
        let stride = self.plan.candidates;
        let mut waves: Vec<Range<usize>> = Vec::new();
        let mut first = 0;
        while first < jobs.len() {
            let origin = jobs[first].bytes.start;
            let mut end = group_end(jobs, first);
            while end < jobs.len() {
                let next = group_end(jobs, end);
                if jobs[next - 1].bytes.end - origin > half {
                    break;
                }
                end = next;
            }
            waves.push(first..end);
            first = end;
        }
        if waves.len() < 2 {
            return false;
        }
        let direct = Direct::new(outs, jobs);
        let mut wave_of = vec![0u32; jobs.len()];
        for (index, wave) in waves.iter().enumerate() {
            for job in wave.clone() {
                wave_of[job] = index as u32;
            }
        }
        let origin_of = |wave: usize| jobs[waves[wave].start].bytes.start;
        let base_of = |wave: usize| (wave % 2) * half * stride;
        let packed: Vec<Mutex<Vec<u8>>> = (0..jobs.len()).map(|_| Mutex::new(Vec::new())).collect();
        let done: Vec<AtomicUsize> = waves.iter().map(|_| AtomicUsize::new(0)).collect();
        let slots_of = |index: usize| {
            let wave = wave_of[index] as usize;
            let at = base_of(wave) + (jobs[index].bytes.start - origin_of(wave)) * stride;
            &self.hints[at..at + jobs[index].bytes.len() * stride]
        };
        let parse = |index: usize| {
            // Counted done when it ends, however it ends: a parse that
            // panicked leaves the driver waiting on no one, and the scope
            // raises the panic when it closes.
            let _done = Counted(&done[wave_of[index] as usize]);
            let job = &jobs[index];
            let block = Block {
                span: slice_of(span, segments, job),
                start: job.bytes.start,
                end: job.bytes.end,
                dictionary: reach,
            };
            let effort = self.effort_for(block, !job.records.is_empty());
            let source = Source::Hints {
                slots: slots_of(index),
                stride,
            };
            let bytes = self.encode_block(
                format,
                block,
                source,
                job.last,
                effort,
                &records[job.records.clone()],
                direct.get(job.out),
                self.chain_slot(&direct, job.segment),
            );
            *packed[index].lock().unwrap_or_else(|e| e.into_inner()) = bytes;
        };
        // `with_tree`'s passes, inside one wave.
        let pass_end = |at: usize, wave_end: usize, ends: &mut Vec<usize>| {
            ends.clear();
            let origin = jobs[at].bytes.start;
            let mut to = group_end(jobs, at);
            ends.push(jobs[to - 1].bytes.end);
            while to < wave_end {
                let next = group_end(jobs, to);
                if jobs[next - 1].bytes.end - origin > WALK_BLOCKS * PARSE_BLOCK_BYTES {
                    break;
                }
                ends.push(jobs[next - 1].bytes.end);
                to = next;
            }
            to
        };
        let mut walk = |pass: Range<usize>, ends: &[usize], wave: usize| {
            let from = base_of(wave) + (jobs[pass.start].bytes.start - origin_of(wave)) * stride;
            let bytes = jobs[pass.start].bytes.start..jobs[pass.end - 1].bytes.end;
            let slots = &self.hints[from..from + bytes.len() * stride];
            // As `with_tree`: only the span's last three positions are
            // left unwritten by the walk.
            let unvisited = span.len().saturating_sub(3).max(bytes.start);
            if bytes.end > unvisited {
                for slot in &slots[(unvisited - bytes.start) * stride..] {
                    slot.store(0, Ordering::Relaxed);
                }
            }
            let width = if bytes.len() < WALK_ALONE_BYTES {
                1
            } else {
                walkers
            };
            tree.advance_ranges(span, bytes.start, ends, Some(slots), stride, width);
        };
        // Wave `wave`'s parses all done: its outputs go to their members,
        // in order, and its buffers back to be handed out again.
        let mut appended = 0;
        let append = |wave: usize, outs: &mut [Vec<u8>]| {
            let want = waves[wave].len();
            let mut spins = 0u32;
            while done[wave].load(Ordering::Acquire) < want {
                spins += 1;
                if spins < 64 {
                    std::hint::spin_loop();
                } else if rayon::yield_now() != Some(rayon::Yield::Executed) {
                    std::thread::yield_now();
                }
            }
            let mut spare = self.spare_outs.lock().unwrap_or_else(|e| e.into_inner());
            for index in waves[wave].clone() {
                let bytes =
                    std::mem::take(&mut *packed[index].lock().unwrap_or_else(|e| e.into_inner()));
                outs[jobs[index].out].extend_from_slice(&bytes);
                keep_out(&mut spare, bytes);
            }
        };
        let mut ends = Vec::new();
        rayon::scope(|scope| {
            for (index, wave) in waves.iter().enumerate() {
                if index >= 2 {
                    append(index - 2, outs);
                    appended = index - 1;
                }
                let mut at = wave.start;
                while at < wave.end {
                    let pass = at..pass_end(at, wave.end, &mut ends);
                    walk(pass.clone(), &ends, index);
                    at = pass.end;
                    for job in pass {
                        let parse = &parse;
                        scope.spawn(move |_| parse(job));
                    }
                }
            }
        });
        for wave in appended..waves.len() {
            append(wave, outs);
        }
        direct.restore(outs);
        true
    }
}
