//! The whole-buffer and streamed entries: a run, a region or a chunk
//! encoded now, and the history forgotten behind it.

use super::*;

/// The longest span [`Engine::forget`] empties by hashing it again rather
/// than clearing the whole head table, as a fraction of the table: past
/// this many positions per head the plain clear is the cheaper of the two.
pub(super) const FORGET_SPAN_PER_HEAD: usize = 4;

/// `span` where a region entry was handed one WHOLE member in one call
/// (no history before it, and its last byte the member's), which is the
/// member [`Engine::start_member`] reads the class of; none otherwise.
pub(super) fn whole_member(span: &[u8], emit_from: usize, last: bool) -> Option<&[u8]> {
    (emit_from == 0 && last).then_some(span)
}

impl Engine {
    /// Encode `chunk` as a run of its own that ends with it: the history
    /// is forgotten first, as [`Engine::reset_history`] does, and the
    /// chunk is a whole member, `plan`'s spans relative to its first byte
    /// ([`Engine::stage_filtered`] at base 0). The bytes are
    /// [`Engine::encode_chunk_filtered`]'s from a fresh history; what differs is
    /// that the chains are sized from the chunk rather than from the
    /// history a longer run could grow to, which at a 2 MiB dictionary is
    /// 64 MiB of links a member of a few KiB never reaches.
    pub(crate) fn encode_whole_run<F: Emit>(
        &mut self,
        format: &F,
        chunk: &[u8],
        out: &mut Vec<u8>,
        plan: &[FilterSpan],
    ) {
        self.start_member(chunk, chunk.len() as u64);
        self.stage_filtered(chunk, true, plan, 0);
        // A run that is one chunk never grows past it, so the chains are
        // sized from what is staged. Their size cannot reach the output
        // (`Chains::new`), and a span that does not wrap is parsed in one
        // wave at either size (`Chains::wave_bytes`). The TREE keeps the
        // history's sizing: its head count follows its geometry and its
        // answers follow its heads. Set here and not in `Engine::flush`,
        // so the path every solid batch takes is not touched.
        if self.plan.finder_for(chunk.len()) == Finder::Chain {
            self.sized_for = self.history.len();
        }
        let packed = &mut self.flush(format)[0];
        if out.is_empty() {
            std::mem::swap(out, packed);
        } else {
            out.append(packed);
        }
    }

    /// The most the history buffer holds: the dictionary, which is all a
    /// match may reach, and the slack it may run into before it is slid
    /// down. A chunk longer than the slack widens it for that chunk,
    /// because a chunk is never split.
    pub(super) fn history_cap(&self, chunk: usize) -> usize {
        self.dictionary
            .saturating_add(self.slack.max(chunk))
            .min(SPAN_BYTES)
    }

    /// Encode one member's bytes.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub(crate) fn encode<F: Emit>(&mut self, format: &F, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_region(format, input, 0, true, &mut out);
        out
    }

    /// Encode the bytes of `span` from `emit_from` on, appending their
    /// blocks to `out` and flagging the last of them only when `last`
    /// says the member ends here.
    ///
    /// **`span[..emit_from]` is HISTORY: bytes the decoder will already
    /// have in its window when it reaches this region, which this call
    /// indexes so that matches reach back into them but emits no token
    /// for.** That is the one thing a member at a time cannot express,
    /// and it is what two shapes of the format need:
    ///
    /// - spec G 3.7.3's WINDOWED encode, where one member's bytes arrive
    ///   a window at a time and each window's history is the window
    ///   before it, so the member is never held whole;
    /// - spec G 3.9's SOLID sets, where a member's history is the member
    ///   before it (spec H3 section 4, which names exactly this state).
    ///
    /// A member is a chain of blocks and nothing else, so a member built
    /// from several calls is the concatenation of what they append; only
    /// the call with `last` flags a block as the member's end.
    ///
    /// The history a call actually indexes is capped at the dictionary,
    /// because nothing farther back can be named by a distance anyway.
    pub(crate) fn encode_region<F: Emit>(
        &mut self,
        format: &F,
        span: &[u8],
        emit_from: usize,
        last: bool,
        out: &mut Vec<u8>,
    ) {
        let member = whole_member(span, emit_from, last);
        self.region_over(format, span, emit_from, last, out, &[], member);
    }

    /// [`Engine::encode_region`] with a filter PLAN (spec H3 section 6.6):
    /// `plan`'s spans are relative to `span[emit_from..]`, and `base` is
    /// the member relative offset of `span[emit_from]`, which is the
    /// transforms' `F` for a span starting there.
    ///
    /// The caller's bytes are borrowed and cannot be transformed where
    /// they lie, so a member with a plan is COPIED and the copy is what the
    /// finder and the parse see. A member with an empty plan is the plain
    /// entry and copies nothing, which is every member on data where no
    /// filter fires.
    ///
    /// **The copy is bounded at [`FILTER_PIECE_BYTES`], 256 MiB.** A span
    /// that long or shorter is copied whole and encoded as one region,
    /// which keeps the parse as wide as the unfiltered member's: the copy
    /// costs the member's size in memory (a 199.6 MB library peaked at 576
    /// MiB against 384 MiB unfiltered) and pieces cost width, and width
    /// won (the constant says where that was measured). A longer span is
    /// encoded as a CARRIED RUN of pieces of that length
    /// ([`Engine::stage_filtered`] and [`Engine::flush`], the path a
    /// reader payload already takes), so what is held beside the caller's
    /// bytes is the history buffer and never the member. A plan's spans
    /// never straddle a piece, because they start on parse block
    /// boundaries and a piece is a whole number of blocks.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn encode_region_filtered<F: Emit>(
        &mut self,
        format: &F,
        span: &[u8],
        emit_from: usize,
        last: bool,
        out: &mut Vec<u8>,
        plan: &[FilterSpan],
        base: u64,
    ) {
        // The member's class is read from its bytes as they are, before
        // any filter transforms them: a reader's head is read that way.
        let member = whole_member(span, emit_from, last);
        if plan.is_empty() {
            return self.region_over(format, span, emit_from, last, out, &[], member);
        }
        let piece = filter_piece_bytes();
        if emit_from == 0 && span.len() > piece {
            match member {
                Some(head) => self.start_member(head, head.len() as u64),
                None => self.reset_history(),
            }
            let mut from = 0;
            let mut at = 0;
            let mut piece_plan = Vec::new();
            while from < span.len() {
                let to = (from + piece).min(span.len());
                piece_plan.clear();
                while at < plan.len() && plan[at].start < to {
                    debug_assert!(
                        plan[at].start + plan[at].len <= to,
                        "a span inside its piece"
                    );
                    piece_plan.push(FilterSpan {
                        start: plan[at].start - from,
                        ..plan[at]
                    });
                    at += 1;
                }
                self.stage_filtered(
                    &span[from..to],
                    last && to == span.len(),
                    &piece_plan,
                    base + from as u64,
                );
                out.append(&mut self.flush(format)[0]);
                from = to;
            }
            return;
        }
        let mut owned = span.to_vec();
        let mut placed = Vec::with_capacity(plan.len());
        for filter in plan {
            let at = emit_from + filter.start;
            encode_in_place(
                filter.kind,
                &mut owned[at..at + filter.len],
                base + filter.start as u64,
                &mut self.filter_scratch,
            );
            placed.push(Placed {
                at,
                len: filter.len,
                kind: filter.kind,
            });
        }
        self.region_over(format, &owned, emit_from, last, out, &placed, member);
    }

    /// The body of both region entries. `placed` names spans already
    /// transformed in `span`, by their positions in it; `member` is the
    /// member's own bytes, untransformed, where `span` is a whole member
    /// ([`whole_member`]), which is what its class is read from.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn region_over<F: Emit>(
        &mut self,
        format: &F,
        span: &[u8],
        emit_from: usize,
        last: bool,
        out: &mut Vec<u8>,
        placed: &[Placed],
        member: Option<&[u8]>,
    ) {
        debug_assert!(emit_from <= span.len());
        // This entry takes its whole history in the span it is handed, so
        // nothing of an earlier run may be carried into it, and its member
        // opens a fresh table set: nothing is written late.
        match member {
            Some(head) => self.start_member(head, head.len() as u64),
            None => self.reset_history(),
        }
        self.defers.clear();
        if emit_from >= span.len() {
            if last {
                // A member with no bytes left is still one last block, so
                // the chain is walkable and the member ends.
                let whole = std::iter::once(0..0).collect::<Vec<_>>();
                format.emit(&[], &whole, true, &[], out);
            }
            return;
        }
        self.lone = self
            .plan
            .lone
            .is_some_and(|lone| emit_from == 0 && last && span.len() <= lone.bytes);
        // The whole member is `span` past its history.
        self.long = span.len() - emit_from > self.narrow_reach();
        let mut shifted = Vec::new();
        let mut from = emit_from;
        while from < span.len() {
            let to = (from + SPAN_BYTES).min(span.len());
            let base = from.saturating_sub(self.dictionary);
            // Never whole: this entry starts its own run, so its member
            // opens a fresh set as every member did before carried sets.
            let segment = Segment {
                start: from - base,
                end: to - base,
                last: last && to == span.len(),
                whole: false,
            };
            // A piece's spans, by their positions in the piece's slice. A
            // plan's spans never straddle a piece: spec G's regions are
            // parse blocks, and a piece is a whole number of them.
            shifted.clear();
            shifted.extend(
                placed
                    .iter()
                    .filter(|span| (from..to).contains(&span.at))
                    .map(|span| {
                        debug_assert!(span.at + span.len <= to, "a span inside its piece");
                        Placed {
                            at: span.at - base,
                            ..*span
                        }
                    }),
            );
            self.encode_span(
                format,
                &span[base..to],
                Region {
                    indexed: 0,
                    fresh: true,
                    sizing: to - base,
                },
                std::slice::from_ref(&segment),
                &shifted,
                std::slice::from_mut(out),
            );
            from = to;
        }
        self.lone = false;
        // Every position this call inserted lies in `span`'s bytes: the
        // FILTERED ones where a plan ran, which is why the copy and not
        // the caller's bytes is what reaches here.
        self.forget(span);
    }

    /// Empty the finder's heads that a run over `span` could have written,
    /// when that is cheaper than clearing them all, so that the next
    /// fresh run can skip the clear (`Engine::tree_clean`, `Engine::chains_clean`).
    ///
    /// Only sound when every position inserted since the heads were last
    /// empty lay in `span`'s bytes, which both callers guarantee: the end
    /// of [`Engine::encode_region`], whose run starts fresh and walks only
    /// `span`, and [`Engine::reset_history`] over a carried history, whose
    /// index is exactly the history's positions. Emptied heads are the
    /// state a clear leaves, and a run's answers read nothing else of the
    /// finder's past, so this moves no byte of output.
    pub(super) fn forget(&mut self, span: &[u8]) {
        match self.walked {
            Finder::Tree => {
                if self.tree_clean {
                    return;
                }
                if let Some(tree) = &self.tree {
                    if span.len() * FORGET_SPAN_PER_HEAD <= tree.newest.len() && tree.forget(span) {
                        self.tree_clean = true;
                    }
                }
            }
            Finder::Chain => {
                if self.chains_clean {
                    return;
                }
                if let Some(chains) = &mut self.chains {
                    if span.len() * FORGET_SPAN_PER_HEAD <= chains.heads.len() {
                        chains.forget(span);
                        self.chains_clean = true;
                    }
                }
            }
        }
    }

    /// Encode `chunk` as the CONTINUATION of whatever this engine
    /// carries, and keep what a later chunk may reach back into.
    ///
    /// This is the entry spec H3 section 4's erratum describes: "an
    /// encoder is an OBJECT that outlives a member, not a function over
    /// one". Between the chunks it carries the output history, which is
    /// the same bytes the decoder's window holds up to the dictionary
    /// size, ALONG WITH THE MATCH FINDER'S INDEX OVER THEM, which is the
    /// part [`Engine::encode_region`] could not express: that entry takes
    /// its history in the span it is handed, so the finder indexes the
    /// history again for every call, and a solid set of sixty-four
    /// members over a four mebibyte dictionary walked 288 MiB to encode
    /// 32. Here the history is indexed ONCE.
    ///
    /// Two shapes of the format use it, and they are one loop in the
    /// writer:
    ///
    /// - spec G 3.7.3's WINDOWED encode, where one member's bytes arrive
    ///   a window at a time and each window continues the one before it,
    ///   so the member is never held;
    /// - spec G 3.9's SOLID sets, where a member continues the member
    ///   before it.
    ///
    /// What does NOT carry is anything the decoder resets at a member
    /// boundary: a member is a chain of blocks and nothing else, so a
    /// member built from several calls is the concatenation of what they
    /// append, only the call with `last` flags a block as the member's
    /// end, and every call's first block carries its own tables. Spec H3
    /// section 4's conservative rule for a solid member's first token is
    /// satisfied because every parse block starts from an empty repeated
    /// distance model, so the first token of any of them is a literal or
    /// a fresh match.
    ///
    /// [`Engine::reset_history`] ends a run. Working memory here is the
    /// history buffer alone, bounded by [`Engine::history_cap`] and so by
    /// the dictionary and [`HISTORY_SLACK_CEIL`], never by the member;
    /// `chunk` is expected to be no longer than the slack, which spec G's
    /// window of at most 8 MiB is.
    pub(crate) fn encode_chunk<F: Emit>(
        &mut self,
        format: &F,
        chunk: &[u8],
        last: bool,
        out: &mut Vec<u8>,
    ) {
        self.encode_chunk_filtered(format, chunk, last, out, &[], 0);
    }

    /// [`Engine::encode_chunk`] with a filter plan: `plan`'s spans are
    /// relative to `chunk`, and `base` is `chunk`'s member relative
    /// offset. [`Engine::stage_filtered`] has the rule.
    pub(crate) fn encode_chunk_filtered<F: Emit>(
        &mut self,
        format: &F,
        chunk: &[u8],
        last: bool,
        out: &mut Vec<u8>,
        plan: &[FilterSpan],
        base: u64,
    ) {
        debug_assert!(
            self.staged.is_empty(),
            "a batch is flushed before a single chunk"
        );
        self.stage_filtered(chunk, last, plan, base);
        let packed = &mut self.flush(format)[0];
        if out.is_empty() && out.capacity() < packed.len() {
            // The buffers change places rather than the bytes, and the
            // engine keeps the one the caller brought, at its capacity.
            // Not where the caller's already holds this chunk: a caller
            // that reserved its buffer for the whole member (a writer
            // under a memory ceiling) would otherwise be handed back the
            // engine's, of one chunk, and grow it again by doubling.
            std::mem::swap(out, packed);
        } else {
            out.append(packed);
        }
    }
}
