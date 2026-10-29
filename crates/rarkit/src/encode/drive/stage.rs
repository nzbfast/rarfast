//! The staged batch: chunks held, outputs lent, and the flush that
//! encodes them as one wave.

use super::*;

impl Engine {
    /// The most bytes one batch stages before it has to be flushed.
    ///
    /// **What a batch costs, in bytes.** Its input is already in the
    /// history buffer and costs nothing extra; what it adds is the
    /// PACKED output of the members the caller has not taken yet, which
    /// is bounded by this. Beside it stand the blocks in flight, which a
    /// batch widens rather than adds: `width` blocks of hints, held to
    /// [`HINT_BUDGET_BYTES`], and one block's tokens and output per block
    /// in flight. Never more than the slack, because a batch that would
    /// slide the history is cut before the slide instead.
    ///
    /// **At a batch of sixty-four** (`BATCH_BLOCKS_MOST` before it was
    /// 256, and what a member at the default dictionary still takes, its
    /// slack being sixty-four blocks), for a member streamed
    /// a window at a time with no ceiling (a caller's ceiling stages a
    /// window a flush and never reaches it), the charge a writer's
    /// admission can take from [`Engine::flight_term`] of the batch:
    ///
    /// - per WAVE, the blocks whose outputs are held until they are
    ///   appended: at most `Chains::wave_bytes` over a parse block, 55 at
    ///   a 2 MiB dictionary where a batch of 32 held 32, each reserved at
    ///   `block_out_bytes` and touched as far as its packed bytes;
    /// - per THREAD, one parse scratch for each block parsed at once, the
    ///   least of that wave and the pool's threads: past 32 threads a
    ///   batch of 64 keeps more of them busy, and so more scratches (a
    ///   block's tokens and the optimal parse's window, about 4.6 MiB at
    ///   level 3);
    /// - per BATCH, nothing of the engine's: the batch's packed bytes go
    ///   into the member's own buffer, lent for the flush
    ///   ([`Engine::lend_first`]).
    pub(super) fn batch_cap(&self) -> usize {
        (batch_blocks() * PARSE_BLOCK_BYTES).min(self.slack)
    }

    /// [`Engine::batch_cap`] of a SOLID run at `dictionary`, whose slack is
    /// the shipped [`HISTORY_SLACK_MULTIPLE`]: what the writer pulls ahead
    /// for the next solid batch (`Run::prefetch_list`). Eight MiB at the
    /// default dictionary, as it was before the batch went to sixty-four.
    pub(crate) fn solid_batch_bytes(dictionary: usize) -> usize {
        let slack = dictionary
            .max(1)
            .saturating_mul(HISTORY_SLACK_MULTIPLE)
            .min(HISTORY_SLACK_CEIL);
        (batch_blocks() * PARSE_BLOCK_BYTES).min(slack)
    }

    /// Whether a chunk of `chunk` bytes may join the batch already staged
    /// without changing a byte of anybody's output.
    ///
    /// Three things end a batch, and each of them is a thing that would
    /// otherwise move a byte or throw the index away:
    ///
    /// - a SLIDE, which drops bytes a staged parse has not read yet, and
    ///   which must therefore happen with nothing in flight;
    /// - a GEOMETRY change, because one finder walks the whole batch and
    ///   its structures are sized from the run's longest span;
    /// - the batch's own cap, which is the packed output it holds. It
    ///   bounds the batch in BYTES and in members both
    ///   ([`BATCH_MEMBERS_MOST`], which says why a member apiece is not
    ///   width enough at the tree's levels).
    ///
    /// An empty batch takes any chunk, so staging always makes progress.
    pub(crate) fn may_stage(&self, chunk: usize) -> bool {
        let Some(first) = self.staged.first() else {
            return true;
        };
        let cap = self.history_cap(chunk);
        self.staged.len() < BATCH_MEMBERS_MOST
            && self.history.len() + chunk <= cap
            && cap <= self.sized_for
            && self.history.len() - first.start + chunk <= self.batch_cap()
    }

    /// Whether a slide of the history now keeps the finder's index rather
    /// than dropping it: where the index is the tree's and the run is
    /// SOLID ([`Plan::wide_ring`] is set for a solid run and only for one).
    ///
    /// A slide may show in a solid archive's bytes, and SPEC-H3
    /// section 4 holds a non-solid member byte identical, so a member
    /// streamed a window at a time outside a solid set still drops the
    /// index and walks the kept dictionary again. The chains' links count
    /// from the span and are dropped too.
    pub(super) fn slide_keeps_index(&self) -> bool {
        self.carried && self.plan.wide_ring && self.walked == Finder::Tree && self.tree.is_some()
    }

    /// Stage one chunk of a carried run: its bytes join the history, and
    /// its packed bytes are produced by the next [`Engine::flush`], which
    /// hands them back in staging order.
    ///
    /// The caller asks [`Engine::may_stage`] first. Staging happens with
    /// nothing in flight, which is what lets the history buffer grow
    /// under it: a parse borrows that buffer only for the length of a
    /// flush.
    pub(crate) fn stage(&mut self, chunk: &[u8], last: bool) {
        self.stage_filtered(chunk, last, &[], 0);
    }

    /// [`Engine::stage`] with a filter plan (spec H3 section 6.6): once
    /// `chunk` has joined the history, each of `plan`'s spans (relative to
    /// `chunk`) is transformed THERE, in the encode direction with `F` its
    /// member relative start (`base` plus its start), so the finder, the
    /// parse and every later match see the bytes the decoder's window
    /// will hold. The history is already a copy, so this copies nothing
    /// more; a chunk with an empty plan does no work here at all.
    pub(crate) fn stage_filtered(
        &mut self,
        chunk: &[u8],
        last: bool,
        plan: &[FilterSpan],
        base: u64,
    ) {
        debug_assert!(self.may_stage(chunk.len()), "the caller asked may_stage");
        let cap = self.history_cap(chunk.len());
        self.sized_for = self.sized_for.max(cap);
        if self.history.len() + chunk.len() > cap {
            debug_assert!(self.staged.is_empty(), "a slide with nothing in flight");
            // Slide: keep the dictionary, which is everything a match may
            // still reach, and drop the rest.
            let keep = self.dictionary.min(self.history.len());
            let stale = self.history.len() - keep;
            self.history.drain(..stale);
            if self.slide_keeps_index() {
                // A SOLID run's tree keeps its index (spec H3 section
                // 4): its positions count from the run's start, so
                // dropping the bytes before the dictionary leaves every
                // slot as it is, and the positions they held are past the
                // window. Nothing is walked again.
                let tree = self.tree.as_mut().expect("a carried tree");
                debug_assert_eq!(tree.next, self.indexed, "the index is whole");
                // The history never outgrows a span, so a span's worth of
                // room past the origin is all the slots must keep.
                tree.slide(stale, SPAN_BYTES);
                self.indexed -= stale;
                self.slid = true;
            } else {
                // Anything else drops the index with the bytes it named,
                // and the next call builds one over what was kept.
                self.indexed = 0;
                self.carried = false;
            }
        }
        // Exactly, so the buffer's capacity is its contents and the
        // working memory this engine reports is the truth. After the
        // first slide it is already at the cap and nothing reallocates.
        //
        // A chunk that does not end its member is a window of a longer
        // one, whose history will run to the cap: it is reserved to the
        // cap at once. Grown a window at a time it was reallocated at
        // every window, and each block it outgrew (2, 4, 6 and 8 MiB at a
        // 2 MiB window) was freed at a size macOS 27.0's allocator keeps
        // RESIDENT in its large-block cache. Pages past what is staged
        // are not touched, and `Engine::held_bytes` counts what is.
        //
        // A whole member that JOINS a history (a solid run) takes room in
        // doubling steps up to the cap ([`history_room`] says why).
        #[cfg(target_os = "linux")]
        let held = (self.history.as_ptr(), self.history.capacity());
        let room = history_room(
            self.history.len(),
            self.history.capacity(),
            chunk.len(),
            cap,
            last,
        );
        self.history.reserve_exact(room - self.history.len());
        #[cfg(target_os = "linux")]
        if held != (self.history.as_ptr(), self.history.capacity()) {
            // A new or a grown block: the room not yet written asks for
            // 2 MiB pages before the chunk lands in it, since a search
            // reads the history wherever its candidates are
            // (`crate::pages`). Only where the advice exists, so that
            // every other target compiles what it always did.
            crate::pages::advise_huge_of(self.history.spare_capacity_mut());
        }
        let start = self.history.len();
        self.history.extend_from_slice(chunk);
        for filter in plan {
            debug_assert!(
                filter.start + filter.len <= chunk.len(),
                "a span inside its chunk"
            );
            let at = start + filter.start;
            encode_in_place(
                filter.kind,
                &mut self.history[at..at + filter.len],
                base + filter.start as u64,
                &mut self.filter_scratch,
            );
            self.placed.push(Placed {
                at,
                len: filter.len,
                kind: filter.kind,
            });
        }
        self.history_most = self.history_most.max(self.history.len());
        self.staged.push(Segment {
            start,
            end: self.history.len(),
            last,
            whole: last && !self.mid_member,
        });
        self.mid_member = !last;
        if self.outs.len() < self.staged.len() {
            self.outs.push(Vec::new());
        }
        self.outs[self.staged.len() - 1].clear();
    }

    /// Give the chunk staged last `out` to write its packed bytes into,
    /// in place of this engine's own buffer for it, which is dropped. A
    /// caller that holds a batch's packed bytes lends buffers from its own
    /// pool, reserved to each member's bound, and takes them back with the
    /// output (`Run::batch_solid`): so no buffer here keeps the capacity
    /// of the largest member its slot ever held, and no buffer regrows,
    /// which on macOS 27.0 left each freed block resident in the
    /// allocator's large-block cache. The bytes are the same in any
    /// buffer.
    pub(crate) fn lend_out(&mut self, mut out: Vec<u8>) {
        let slot = self.staged.len().checked_sub(1).expect("a chunk is staged");
        out.clear();
        self.outs[slot] = out;
    }

    /// Give the FIRST chunk staged `out` to append its packed bytes to,
    /// after the bytes `out` already holds; the next [`Engine::flush`]
    /// hands it back as that chunk's output.
    ///
    /// For a member staged a window at a time (`write::engine`'s
    /// `flush_windows`): the writer lends the member's own packed buffer,
    /// and every later window of the same member in the batch appends to
    /// the same buffer (`Job::out`), so the batch's packed bytes go
    /// straight to the member and no buffer of the engine's holds them on
    /// the way. At a batch of [`BATCH_BLOCKS_MOST`] that way-station was
    /// up to 16 MiB of packed bytes a flush, resident between flushes
    /// (bin4g at `-m3`: `phys_footprint` 15 to 20 MiB over the batch of
    /// 32 at 4 and 16 threads). The bytes are the
    /// same in any buffer, in the same order.
    pub(crate) fn lend_first(&mut self, out: Vec<u8>) {
        assert!(!self.staged.is_empty(), "a chunk is staged");
        self.outs[0] = out;
    }

    /// Parse every staged chunk as ONE wave, and hand back their packed
    /// bytes in staging order.
    ///
    /// **This is where a solid set stops joining at every member.** The
    /// wave spans the batch: the blocks of one member are still being
    /// parsed on other threads while the finder walks the member after
    /// it, and the wave empties only when it is full. Nothing a block's
    /// parse reads has changed, which is why the bytes cannot: its block
    /// is its own member's, the slice it and the finder are handed stops
    /// at that member's end ([`Segment`] says why that is load bearing),
    /// the finder takes the same positions in the same order, and the
    /// tree's parse reads only the hints its own block's walk left.
    ///
    /// The buffers are this engine's and are reused; a caller that wants
    /// to keep one swaps its own in.
    pub(crate) fn flush<F: Emit>(&mut self, format: &F) -> &mut [Vec<u8>] {
        let count = self.staged.len();
        let blocks: usize = self.staged.iter().map(|segment| segment.blocks()).sum();
        // Which members are written late, by the carried-set chains.
        let defers = F::CARRIES && !self.carry_off;
        self.defers.clear();
        self.defers.extend(self.staged.iter().map(|segment| {
            defers && segment.whole && segment.end - segment.start < CARRY_MEMBER_BYTES
        }));
        self.plan_chains();
        // A member with no bytes left is still one last block, so the
        // chain is walkable and the member ends. It asks nothing of a
        // finder, which is why it is emitted here and not as a job; a
        // whole one takes its place in the chain of table sets.
        for index in 0..count {
            let segment = self.staged[index];
            if segment.blocks() == 0 && segment.last {
                let whole = std::iter::once(0..0).collect::<Vec<_>>();
                if self.defers[index] {
                    let empty = Deferred {
                        tokens: Vec::new(),
                        cuts: whole,
                        records: Vec::new(),
                        counts: Vec::new(),
                    };
                    self.member_parsed(format, index, empty, None);
                } else {
                    format.emit(&[], &whole, true, &[], &mut self.outs[index]);
                }
            }
        }
        if blocks == 0 {
            // Nothing to parse, so nothing of the finders is touched.
            let mut outs = std::mem::take(&mut self.outs);
            self.finish_chains(format, &mut outs[..count]);
            self.outs = outs;
            self.staged.clear();
            self.placed.clear();
            return &mut self.outs[..count];
        }
        let region = Region {
            indexed: if self.carried { self.indexed } else { 0 },
            fresh: !self.carried,
            sizing: self.sized_for,
        };
        // The span the finder walks is this engine's own buffer, so it is
        // taken out for the call and put back: nothing else reads it in
        // between, and the buffer's memory is kept either way. The same
        // goes for the batch and for the outputs it fills.
        // One member from no history, whole in this one chunk, is as lone
        // here as through `encode_region`: a windowed member that fits one
        // window.
        self.lone = self.plan.lone.is_some_and(|lone| {
            region.fresh
                && matches!(self.staged[..], [only] if only.start == 0 && only.last && only.end <= lone.bytes)
        });
        // A run's first member decides it at its first window: a member of
        // more windows than one is longer than a window, which is the
        // dictionary wherever the wide ring can apply (spec G 3.7.3, at
        // most 4 MiB), so longer than the reach; one of one window is its
        // window's length. Its later windows keep what it decided.
        if region.fresh {
            self.long = self
                .staged
                .first()
                .is_some_and(|first| !first.last || first.end - first.start > self.narrow_reach());
        }
        let history = std::mem::take(&mut self.history);
        let segments = std::mem::take(&mut self.staged);
        let mut outs = std::mem::take(&mut self.outs);
        let placed = std::mem::take(&mut self.placed);
        self.encode_span(
            format,
            &history,
            region,
            &segments,
            &placed,
            &mut outs[..count],
        );
        self.finish_chains(format, &mut outs[..count]);
        self.lone = false;
        self.history = history;
        self.placed = placed;
        self.placed.clear();
        self.outs = outs;
        self.staged = segments;
        self.staged.clear();
        self.indexed = self.history.len();
        self.carried = true;
        &mut self.outs[..count]
    }
}

/// The capacity the history buffer is given before a chunk of `chunk`
/// bytes joins the `len` it holds in a block of `capacity`, under a cap of
/// `cap` ([`Engine::history_cap`]).
///
/// - A block with the room keeps its capacity.
/// - A chunk that does not end its member (`last` false) is a window of
///   a longer one, whose history will run to the cap: the cap at once.
/// - A whole member staged on an EMPTY history takes exactly its bytes:
///   every member of a non-solid archive, and a solid run's first.
/// - A whole member that joins a history takes twice the block, the cap
///   at most. Given exactly its own bytes each time, a solid run of
///   20,000 members of 8 KiB moved its block about 12,000 times on the
///   way to a 32 MiB dictionary's cap (counted on x86-64 Linux, 10 Oct
///   2026: 12,149 `mremap` calls against 1,141 at a 2 MiB dictionary, and
///   0.15 to 0.55 s of system time in a create of 1.1 s).
///
/// Capacity only: [`Engine::held_bytes`] counts the bytes staged, and no
/// byte written depends on where the block ends.
pub(crate) fn history_room(
    len: usize,
    capacity: usize,
    chunk: usize,
    cap: usize,
    last: bool,
) -> usize {
    let needed = len + chunk;
    if !last && capacity < cap {
        return cap.max(needed);
    }
    if needed <= capacity {
        return capacity;
    }
    if len == 0 {
        return needed;
    }
    capacity.saturating_mul(2).min(cap).max(needed)
}
