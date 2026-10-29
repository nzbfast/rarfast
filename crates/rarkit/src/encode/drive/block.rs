//! One block and one span: the effort a block gets, its parse and its
//! bytes, and the outputs written in place.

use super::*;

impl Engine {
    /// Parse, cut and entropy code one block.
    /// What effort this block is parsed at: the level's plan, or the floor
    /// when the incompressible sample says there is nothing here to find.
    ///
    /// A pure function of the block's own bytes, taken on the thread that
    /// parses it and reading nothing outside it, so it cannot move a byte
    /// with the thread count (API promise 6). A level already at the floor
    /// skips the sample: there is nothing under it to drop to.
    ///
    /// **A block carrying a filter record at level 3 takes the LAZY parse
    /// over the level's own chains** (decided
    /// 27 Sep 2026). Filtered media samples as compressible where the
    /// same bytes unfiltered sampled as not and ran at the floor, so the
    /// optimal parse made a filtered member cost 2.4x the instructions of
    /// an unfiltered one; the lazy parse keeps nearly all of the filter's
    /// gain for about 1.4x on audio and LESS than the unfiltered member on
    /// images. The tree levels walk every
    /// position whatever the parse, so the choice buys them nothing and
    /// they keep their plan. A bench build may override it for every
    /// level (`RARKIT_FILTER_EFFORT`).
    pub(super) fn effort_for(&self, block: Block<'_>, filtered: bool) -> Plan {
        if let Some(lone) = self.plan.lone().filter(|_| self.lone) {
            // A lone member is at most one block. Under the sample's floor
            // (32 KiB) it is never sampled and takes its lone effort; from
            // the floor up it is sampled first like any block and may drop
            // to the floor (SPEC-H3 8.1,
            // "(b)"): the sample is for the
            // incompressible member, and a compressible one loses nothing.
            return if sample::worth_searching(&block.span[block.start..block.end]) {
                lone
            } else {
                // The lone effort's own floor, over the finder it walks.
                lone.floor()
            };
        }
        if filtered {
            match filtered_effort() {
                FilteredEffort::Floor => return self.plan.floor(),
                FilteredEffort::Lazy => {
                    return Plan {
                        parse: Parse::Lazy,
                        ..self.plan
                    }
                }
                FilteredEffort::Level => {}
                FilteredEffort::Shipped => {
                    if self.plan.parse == Parse::Optimal && self.plan.finder == Finder::Chain {
                        return Plan {
                            parse: Parse::Lazy,
                            ..self.plan
                        };
                    }
                }
            }
        }
        if self.plan.at_floor() {
            return self.plan;
        }
        let reading = sample::yield_per_mille(&block.span[block.start..block.end]);
        if !sample::worth(reading) {
            // A lone member above keeps the lazy floor: it is at most one
            // block of 256 KiB, and its bytes stay as they are;
            // the scan is for the long runs of media.
            return self.plan.for_empty_block();
        }
        // A thin block at level 3 takes the thin scan; a block carrying a
        // filter record keeps the parse chosen for it above.
        let thin = thin_scan();
        if self.plan.scans_thin && !filtered && sample::thin(reading, thin.under) {
            return self.plan.for_thin_block(thin.links);
        }
        self.plan
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn encode_block<F: Emit>(
        &self,
        format: &F,
        block: Block<'_>,
        source: Source<'_>,
        last: bool,
        effort: Plan,
        records: &[BlockRecord],
        direct: Option<&Mutex<Vec<u8>>>,
        chain: Option<(&Direct, usize)>,
    ) -> Vec<u8> {
        let held = self
            .scratches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop();
        let mut scratch = held.unwrap_or_else(|| Scratch {
            // Sized from the LEVEL's plan and never from a block's
            // effort, so that a block dropped to the floor still hands
            // back a scratch the next block can parse optimally with. A
            // lone member's optimal parse counts too: a lazy level can
            // still hand one to the optimal chain parse.
            optimal: self.plan.parses_optimally().then(OptimalScratch::new),
            model: PriceModel::new(format),
            tokens: Vec::new(),
            cuts: Vec::new(),
            counts: Vec::new(),
            tokens_most: 0,
        });
        let tokens = &mut scratch.tokens;
        tokens.clear();
        scratch.counts.clear();
        match effort.parse {
            // The fast parse cuts its entropy blocks blind and counts
            // their symbols as its tokens go out (`cut::cut_blind`'s cuts
            // and the emitter's counts, without their passes).
            Parse::Fast => match source {
                Source::Chains { chains, .. } => fast_parse(
                    format,
                    block,
                    chains,
                    tokens,
                    &mut scratch.cuts,
                    &mut scratch.counts,
                ),
                Source::Hints { .. } => unreachable!("the fast parse reads the chains"),
            },
            Parse::Lazy => lazy_parse(
                format,
                block,
                source,
                &mut scratch.model,
                tokens,
                effort.back,
            ),
            Parse::Scan => {
                let (stride, least) = scan_geometry();
                // An empty block may be linked at the empty stride only
                // into chains keyed on four bytes.
                let phases = match source {
                    Source::Chains { chains, .. } if chains.key() == KEY_SHORT => self.empty_stride,
                    _ => 1,
                };
                floor_scan(format, block, source, tokens, stride, least, phases)
            }
            Parse::ThinScan => {
                let thin = thin_scan();
                if thin.paired && thin.stride == 1 {
                    lz_thin_scan(format, block, source, tokens, thin.least)
                } else {
                    floor_scan(format, block, source, tokens, thin.stride, thin.least, 1)
                }
            }
            Parse::Optimal => optimal_parse(
                format,
                block,
                source,
                &mut scratch.model,
                scratch.optimal.as_mut().expect("the optimal scratch"),
                effort.dials,
                effort.back,
                tokens,
            ),
        }
        scratch.tokens_most = scratch.tokens_most.max(tokens.len());
        // The steady writer is the fast parse's: its blocks are nearly all
        // literals, and every other parse's write faster held
        // (`BitWriter::steady`).
        let steady = effort.parse == Parse::Fast;
        if effort.parse != Parse::Fast {
            cut::cut_counting(format, tokens, &mut scratch.cuts, &mut scratch.counts);
        }
        if let Some((all, segment)) = chain {
            // A whole small member of a solid run: written by its chain
            // once the members before it are, since whether it opens a
            // table set depends on theirs. Copied, so the
            // scratch keeps its capacity for the next block.
            let mut counts = Vec::new();
            format.add_counts(tokens, &scratch.cuts, records, &mut counts);
            let deferred = Deferred {
                tokens: tokens.clone(),
                cuts: scratch.cuts.clone(),
                records: records.to_vec(),
                counts,
            };
            self.scratches
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(scratch);
            self.member_parsed(format, segment, deferred, Some(all));
            return Vec::new();
        }
        if let Some(direct) = direct {
            // The block is its member's only one: it goes straight into
            // the member's own buffer ([`Direct`]).
            let mut out = direct.lock().unwrap_or_else(|e| e.into_inner());
            format.emit_counted(
                tokens,
                &scratch.cuts,
                &scratch.counts,
                steady,
                last,
                records,
                &mut out,
            );
            drop(out);
            self.scratches
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(scratch);
            return Vec::new();
        }
        let mut out = self
            .spare_outs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
            .unwrap_or_default();
        out.clear();
        out.reserve(block_out_bytes(block.end - block.start));
        format.emit_counted(
            tokens,
            &scratch.cuts,
            &scratch.counts,
            steady,
            last,
            records,
            &mut out,
        );
        self.scratches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(scratch);
        out
    }

    /// Walk and parse the blocks of `segments`, appending each segment's
    /// blocks to its own buffer in `outs`.
    ///
    /// One finder walks the whole call, which is what makes a batch worth
    /// staging and what [`Engine::may_stage`] protects: the geometry is
    /// chosen once here.
    pub(super) fn encode_span<F: Emit>(
        &mut self,
        format: &F,
        span: &[u8],
        region: Region,
        segments: &[Segment],
        placed: &[Placed],
        outs: &mut [Vec<u8>],
    ) {
        let mut jobs = std::mem::take(&mut self.jobs);
        jobs.clear();
        let mut records = Vec::new();
        let mut out = 0;
        for (index, segment) in segments.iter().enumerate() {
            let count = segment.blocks();
            // A segment that continues the member of the one before it
            // (which did not end it, and had blocks of its own) appends to
            // that one's buffer: the writer concatenates a member's
            // windows in order either way (`Engine::lend_first`).
            let continues =
                index > 0 && !segments[index - 1].last && segments[index - 1].blocks() > 0;
            if !(continues && merge_windows()) {
                out = index;
            }
            for within in 0..count {
                let bytes = segment.block(within);
                let from = records.len();
                if !placed.is_empty() {
                    records_for(placed, bytes.clone(), &mut records);
                }
                jobs.push(Job {
                    segment: index,
                    out,
                    within,
                    bytes,
                    last: segment.last && within + 1 == count,
                    records: from..records.len(),
                });
            }
        }
        let blocks = jobs.len();
        let finder = self.finder_now();
        self.walked = finder;
        match finder {
            Finder::Tree => {
                let stride = self.plan.candidates;
                // The tree's geometry is a function of the dictionary and
                // of the run's longest span and of nothing else, so a
                // member's bytes cannot depend on the members before it; a
                // tree of the right geometry is kept, and any other is
                // replaced, which costs the index it held.
                let needed = self.dictionary.min(region.sizing);
                let (ring, cyclic) = self.tree_geometry(region.sizing, self.long);
                // A tree of another geometry is dropped BEFORE its
                // replacement is built: held as the match's scrutinee it
                // stayed alive through the build, and a set whose members
                // straddle two geometries held both, up to 30 MiB more
                // than either (the lead encoder
                // under a tight budget). The bytes are the same either way.
                let kept = self
                    .tree
                    .take()
                    .filter(|tree| tree.cyclic_mask + 1 == cyclic);
                let (mut tree, region) = match kept {
                    Some(tree) => (tree, region),
                    None => (BucketTrees::new(ring), region.rebuilt()),
                };
                debug_assert_eq!(tree.cyclic_mask + 1, cyclic);
                let window = needed.min(cyclic - 1 - TREE_SKEW_BOUND);
                tree.cut = self.plan.depth;
                tree.window = window;
                if region.fresh {
                    // A run starts from empty hash heads. The slots under
                    // them need no clearing: a descent reaches only what a
                    // head names, and a position writes both of its own
                    // slots when it is inserted. A tree just built, or one
                    // whose heads were forgotten, has none to clear.
                    if !self.tree_clean {
                        for head in &tree.newest {
                            head.store(0, Ordering::Relaxed);
                        }
                    }
                    tree.next = 0;
                    tree.origin = 0;
                    self.slid = false;
                }
                self.tree_clean = false;
                debug_assert_eq!(tree.next, region.indexed);
                let width = self.hint_width(stride, blocks, segments.len());
                if self.hints.len() < width * PARSE_BLOCK_BYTES * stride {
                    // Built for the widest flush the run planned, so they
                    // are built once (`Engine::plan_flush`); the walk
                    // below uses `width` of them either way. The old hints
                    // go first, as the tree above does.
                    let most = width.max(self.hint_width(stride, self.flush_blocks, 1));
                    self.hints = Vec::new();
                    self.hints = empty_slots(most * PARSE_BLOCK_BYTES * stride);
                }
                self.with_tree(
                    format, span, region, segments, &jobs, &records, width, &mut tree, outs,
                );
                self.tree = Some(tree);
            }
            Finder::Chain => {
                // Chains that do not hold go before their replacement is
                // built, as the tree's do.
                let kept = self
                    .chains
                    .take()
                    .filter(|chains| chains.holds(region.sizing));
                let (mut chains, region) = match kept {
                    Some(chains) => (chains, region),
                    None => (
                        Chains::new(
                            self.dictionary,
                            region.sizing,
                            self.wave,
                            self.plan.chain_key(),
                        ),
                        region.rebuilt(),
                    ),
                };
                if region.fresh && !self.chains_clean {
                    chains.heads.fill(0);
                }
                self.chains_clean = false;
                self.with_chains(
                    format,
                    span,
                    region,
                    segments,
                    &jobs,
                    &records,
                    &mut chains,
                    outs,
                );
                self.chains = Some(chains);
            }
        }
        self.jobs = jobs;
    }
}

/// The slice a block's segment is walked and parsed over: the span cut
/// off at that member's own end. [`Segment`] says why that cut is the
/// byte identity and not tidiness.
pub(super) fn slice_of<'a>(span: &'a [u8], segments: &[Segment], job: &Job) -> &'a [u8] {
    &span[..segments[job.segment].end]
}

/// Where the walk's group that starts at `at` ends: at most
/// [`WALK_BLOCKS`] blocks, all of them one segment's, counted from that
/// segment's own first block. A batch of one member therefore walks in
/// exactly the groups a member at a time walked in, and no wave or pass
/// cuts one ([`Engine::with_tree`]).
pub(super) fn group_end(jobs: &[Job], at: usize) -> usize {
    let job = &jobs[at];
    let stop = job.within - job.within % WALK_BLOCKS + WALK_BLOCKS;
    let mut to = at + 1;
    while to < jobs.len() && jobs[to].segment == job.segment && jobs[to].within < stop {
        to += 1;
    }
    to
}

/// The output buffers of the members a flush encodes in ONE parse block,
/// taken out of the caller's `outs` for the flush so the block's parse can
/// emit straight into its member's buffer, with no block buffer between
/// (`Engine::encode_block`).
///
/// A solid batch of small members is hundreds of one-block members, and
/// each took a block buffer that was appended to its member and then kept
/// or freed: freed, on macOS 27.0, into an allocator cache that stays
/// resident (bin4g at -m1 -s: 781 MiB of RSS against the earlier code's 218). A
/// member of several blocks still appends them in order. Which buffer a
/// block is emitted into moves no byte.
pub(super) struct Direct(Vec<Option<Mutex<Vec<u8>>>>);

impl Direct {
    pub(super) fn new(outs: &mut [Vec<u8>], jobs: &[Job]) -> Direct {
        let mut count = vec![0usize; outs.len()];
        for job in jobs {
            count[job.out] += 1;
        }
        Direct(
            outs.iter_mut()
                .zip(count)
                .map(|(out, blocks)| (blocks <= 1).then(|| Mutex::new(std::mem::take(out))))
                .collect(),
        )
    }

    pub(super) fn get(&self, segment: usize) -> Option<&Mutex<Vec<u8>>> {
        self.0[segment].as_ref()
    }

    pub(super) fn restore(self, outs: &mut [Vec<u8>]) {
        for (out, direct) in outs.iter_mut().zip(self.0) {
            if let Some(direct) = direct {
                *out = direct.into_inner().unwrap_or_else(|e| e.into_inner());
            }
        }
    }
}

/// Give a block's output buffer back to the pool the next wave's blocks
/// take theirs from ([`Engine::spare_outs`]), while the pool holds fewer
/// than [`spare_outs_most`]; otherwise drop it.
///
/// A buffer keeps the capacity of the largest block it ever held, and a
/// pool as wide as the widest wave is right while a wave is at most sixteen
/// blocks. A solid batch's wave can be hundreds of small members' blocks
/// (the solid -m5 work's batching), and a pool that wide, each buffer
/// grown by a full block of incompressible bytes, held hundreds of MiB:
/// bin4g at -m3 -s and -m5 -s peaked at 759 to 829 MiB of RSS against
/// the earlier code's 216 to 250 (the real-binaries count). Which buffer a block
/// writes into moves no byte.
pub(super) fn keep_out(spare: &mut Vec<Vec<u8>>, mut bytes: Vec<u8>) {
    if bytes.capacity() > 0 && spare.len() < spare_outs_most() {
        bytes.clear();
        spare.push(bytes);
    }
}
