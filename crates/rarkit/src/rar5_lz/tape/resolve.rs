//! The repeat registers resolved ahead of the apply: each block's
//! repeats made distances on the lanes, the checked replay, and the
//! hints the tests read.

use super::*;

/// THE STATE A RESOLVED TAPE LEAVES BEHIND, in terms of the state it finds
/// ([`resolve_repeats`]). Slot `j` is a distance of the tape itself where
/// bit `j` of `known` is set, and otherwise the INCOMING slot `slots[j]`;
/// the last length is the tape's own where `last_known`, and otherwise the
/// incoming one, untouched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RepeatEnd {
    pub(super) slots: [u32; 4],
    pub(super) known: u8,
    pub(super) last: u32,
    pub(super) last_known: bool,
}

impl RepeatEnd {
    /// Turn the state the tape found into the state it leaves.
    #[inline(always)]
    pub(super) fn settle(&self, state: &mut MatchState) {
        let incoming = state.repeats;
        for (j, slot) in state.repeats.iter_mut().enumerate() {
            *slot = if self.known >> j & 1 != 0 {
                self.slots[j] as usize
            } else {
                incoming[self.slots[j] as usize & 3]
            };
        }
        if self.last_known {
            state.last_length = self.last as usize;
        }
    }
}

#[cfg(test)]
impl RepeatEnd {
    /// [`RepeatEnd::settle`], for the unit tests.
    pub(crate) fn settle_for_test(&self, state: &mut MatchState) {
        self.settle(state);
    }
}

/// The four slots of a SYMBOLIC ring, slot 0 in `a` to slot 3 in `d`:
/// four scalars
/// rather than one `u128`, so a `REP` picks its slot by the bits of its
/// index and moves the slots below it back one, with no variable shift and
/// no mask table, and all four stay in registers.
#[cfg(feature = "parallel")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ring {
    pub(super) a: u32,
    pub(super) b: u32,
    pub(super) c: u32,
    pub(super) d: u32,
}

#[cfg(feature = "parallel")]
impl Ring {
    /// Slot `j` standing for incoming slot `j`.
    pub(crate) const SEEDED: Ring = Ring {
        a: 0,
        b: 1,
        c: 2,
        d: 3,
    };

    /// A fresh match: every slot moves back one, `distance` takes slot 0.
    #[inline(always)]
    pub(crate) fn push(&mut self, distance: u32) {
        self.d = self.c;
        self.c = self.b;
        self.b = self.a;
        self.a = distance;
    }

    /// A `REP` of index `k`, at most 3: answers slot `k`, moves the slots
    /// below it back one and puts the answer at slot 0; the slots above
    /// `k` stay.
    #[inline(always)]
    pub(crate) fn take(&mut self, k: usize) -> u32 {
        use core::hint::select_unpredictable as pick;
        let even = k & 1 == 0;
        let low = pick(even, self.a, self.b);
        let high = pick(even, self.c, self.d);
        let chosen = pick(k < 2, low, high);
        self.d = pick(k >= 3, self.c, self.d);
        self.c = pick(k >= 2, self.b, self.c);
        self.b = pick(k >= 1, self.a, self.b);
        self.a = chosen;
        chosen
    }

    /// Slot 0.
    #[inline(always)]
    pub(crate) fn first(self) -> u32 {
        self.a
    }

    /// The four slots, slot 0 first.
    #[inline(always)]
    pub(crate) fn slots(self) -> [u32; 4] {
        [self.a, self.b, self.c, self.d]
    }

    /// A ring holding `slots`, slot 0 first, for the unit tests.
    #[cfg(test)]
    pub(crate) fn from_slots([a, b, c, d]: [u32; 4]) -> Ring {
        Ring { a, b, c, d }
    }
}

/// RESOLVE THE TAPE'S REPEATS ON THE DECODE LANE,
/// all or nothing; answers
/// whether it did.
///
/// **Why a lane can.** The repeated distances a `REP` reads are the apply
/// stage's, but within one tape they are a pure function of the state the
/// tape finds and the tape's own operations: a fresh match puts its
/// distance at slot 0, a `REP` permutes the slots, and nothing else writes
/// them. Walking the tape with every slot standing for "incoming slot j"
/// tells, for each repeat, whether the slot it reads is a distance of THIS
/// tape. Each repeat whose slot is becomes a `MATCH` of that distance (and,
/// for a `REP_LAST`, length), saying what it was in [`WAS_SHIFT`]'s bits;
/// one that reads the incoming state stays as decoded, which is allowed
/// only in the first [`LIVE_WITHIN`] ops. [`BlockTape::resolved`] then
/// holds the state the tape leaves in terms of the one it finds, and
/// [`apply_resolved`] walks it with no state traffic: the residue is a
/// repeat's copy address waiting on the state the operation before it
/// stored (measured as the repeat path on the apply thread).
///
/// **Which tapes.** One whose first [`GATE_SAMPLE`] ops hold a repeat in
/// [`GATE_EVERY`] or more; everything else keeps the control's walk and pays that
/// sample alone. Not a parked or failed tape (the serial path finishes
/// those from the live state), not one the far prefetch's gate admits (the
/// shipped walks hint those; [`apply_resolved`] does not), not one holding
/// a zero distance or a length the spare bits would collide with, and never
/// with the measuring arms, which time the shipped walk. ONE pass writes as
/// it walks and puts back what it wrote when a tape turns out unresolvable.
#[cfg(feature = "parallel")]
#[inline(never)]
pub(crate) fn resolve_repeats(tape: &mut BlockTape) -> bool {
    tape.resolved = None;
    if cfg!(feature = "h2-apply-arms") || tape.parked_at.is_some() || tape.failure.is_some() {
        return false;
    }
    let sample = &tape.steps[..tape.steps.len().min(GATE_SAMPLE)];
    let repeats = sample
        .iter()
        .filter(|op| op.kind().wrapping_sub(tape_kind::REP) < 2)
        .count();
    if repeats * GATE_EVERY < sample.len() || far_gate_admits(&tape.steps) {
        return false;
    }
    let mut ring = Ring::SEEDED;
    let mut known = 0u8;
    let mut last = 0u32;
    let mut last_known = false;
    for at in 0..tape.steps.len() {
        let op = tape.steps[at];
        let length = op.length() as u32;
        // The prefix rides along untouched in every rewrite below.
        let prefix = op.kind_length & (LENGTH_MASK << LENGTH_BITS);
        match op.kind() {
            tape_kind::MATCH => {
                // A zero distance is a fault at the match itself, and a
                // slot a repeat reads must never be zero: left to the
                // shipped walk, which raises it where it always did.
                if op.distance == 0 {
                    return unwind(tape, at);
                }
                ring.push(op.distance);
                known = (known << 1 | 1) & 0xF;
                last = length;
                last_known = true;
            }
            tape_kind::REP => {
                let k = op.distance as usize;
                if k > 3 {
                    return unwind(tape, at);
                }
                let own = known >> k & 1 != 0;
                if !own && at >= LIVE_WITHIN {
                    return unwind(tape, at);
                }
                let chosen = ring.take(k);
                let bit = (known >> k) & 1;
                known = (known & !((2u8 << k) - 1) & 0xF) | (known & ((1u8 << k) - 1)) << 1 | bit;
                last = length;
                last_known = true;
                if own {
                    tape.steps[at] = TapeOp {
                        kind_length: (tape_kind::MATCH << TAPE_KIND_SHIFT)
                            | (k as u32 + 1) << WAS_SHIFT
                            | prefix
                            | length,
                        distance: chosen,
                    };
                }
            }
            tape_kind::REP_LAST => {
                if known & 1 != 0 && last_known {
                    tape.steps[at] = TapeOp {
                        kind_length: (tape_kind::MATCH << TAPE_KIND_SHIFT)
                            | WAS_REP_LAST << WAS_SHIFT
                            | prefix
                            | last,
                        distance: ring.first(),
                    };
                } else if at >= LIVE_WITHIN {
                    return unwind(tape, at);
                }
            }
            _ => {}
        }
    }
    tape.resolved = Some(RepeatEnd {
        slots: ring.slots(),
        known,
        last,
        last_known,
    });
    true
}

/// Put back every repeat [`resolve_repeats`] rewrote before `at`, exactly
/// as it was decoded, and answer that the tape was not resolved.
#[cfg(feature = "parallel")]
#[cold]
#[inline(never)]
pub(super) fn unwind(tape: &mut BlockTape, at: usize) -> bool {
    for op in &mut tape.steps[..at] {
        if op.kind() == tape_kind::MATCH {
            let prefix = op.prefix();
            match op.kind_length >> WAS_SHIFT & 7 {
                0 => {}
                WAS_REP_LAST => *op = TapeOp::new(tape_kind::REP_LAST, 0, 0).after(prefix),
                was => *op = TapeOp::new(tape_kind::REP, op.length(), was - 1).after(prefix),
            }
        }
    }
    false
}

/// Apply one RESOLVED tape ([`resolve_repeats`]), in archive order: the
/// shipped arm of [`apply_walk`] line for line, less the match state. Every
/// copy reads its distance and length from its own op, nothing is stored
/// per operation, and the state is set ONCE at the tape's end from
/// [`RepeatEnd`]. Until then `state` is the state the tape FOUND, which is
/// what a repeat kept as decoded replays from and what a stop or an error
/// part way replays from ([`replay_to`], cold), so no caller can tell the
/// two walks apart.
///
/// **WHY A THIRD WALK AND NOT AN ARM IN [`apply_walk`].** Any new branch
/// inside the inlined shipped walk reshapes it on M3 for every row (the
/// repeat work's forms showed it). Chosen once a tape by the
/// apply stage, as [`apply_listed`] is, this leaves [`apply`] the control's source
/// and the control's code for every tape not resolved. `dyn` over the sink for
/// [`apply_listed`]'s reason: one instance, compiled beside none of
/// [`apply`]'s.
#[cfg(feature = "parallel")]
#[inline(never)]
pub(crate) fn apply_resolved(
    tape: &BlockTape,
    end: RepeatEnd,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut dyn LzSink,
) -> Result<TapeApplied> {
    let sink = &mut DynSink(sink);
    filters.offload = filters::offload_wanted();
    let mut literals = 0usize;
    let mut records = 0usize;
    let ops = &tape.steps[..];
    let mut budget = window.apply_budget();
    for op in ops {
        let prefix = op.prefix();
        let length = op.length();
        let kind = op.kind();
        let bytes = prefix + length;
        if bytes > budget || kind >= tape_kind::REP {
            if window.drain_due() {
                if let Err(err) = window.drain(sink, filters, false) {
                    replay_to(ops, op, false, state);
                    return Err(err);
                }
            }
            // The prefix first, cut to the drain cadence as `apply_checked`
            // cuts it; a stop there is BEFORE the operation, so the state
            // replays to it and not through it.
            let prefix = checked_prefix(tape, prefix, &mut literals, window, filters, sink);
            if let Err(err) = prefix {
                replay_to(ops, op, false, state);
                return Err(err);
            }
            let applied = resolved_checked(
                tape,
                ops,
                op,
                &mut literals,
                &mut records,
                state,
                window,
                filters,
                unpacked,
                sink,
            );
            if let Err(err) = applied {
                replay_to(ops, op, true, state);
                return Err(err);
            }
            budget = window.apply_budget();
            continue;
        }
        let run = &tape.verbatim[literals..];
        literals += prefix;
        window.literals_padded(run, prefix);
        if kind == tape_kind::MATCH {
            if let Err(err) = window.copy_match(op.distance as usize, length) {
                replay_to(ops, op, true, state);
                return Err(err);
            }
        }
        budget -= bytes;
    }
    end.settle(state);
    Ok(TapeApplied::BlockDone)
}

/// One operation of a resolved tape with every check in place, its prefix
/// already applied: [`apply_checked`] for the kinds a resolved tape holds. A repeat kept as
/// decoded reads the live state, replayed to it from the state the tape
/// found (at most [`LIVE_WITHIN`] ops); `state` itself is not written.
#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub(super) fn resolved_checked(
    tape: &BlockTape,
    ops: &[TapeOp],
    op: &TapeOp,
    literals: &mut usize,
    records: &mut usize,
    state: &MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut DynSink<'_>,
) -> Result<()> {
    let length = op.length();
    match op.kind() {
        tape_kind::LITS => Ok(()),
        tape_kind::MATCH => window.copy_match(op.distance as usize, length),
        tape_kind::REP => {
            let mut live = *state;
            replay_ops(&ops[..index_of(ops, op)], &mut live);
            let distance = live.rotate_outlined(op.distance as usize, length);
            if distance == 0 {
                return Err(fault::uninitialised_repeat());
            }
            window.copy_match(distance, length)
        }
        tape_kind::REP_LAST => {
            let mut live = *state;
            replay_ops(&ops[..index_of(ops, op)], &mut live);
            if live.last_length != 0 {
                window.copy_match(live.repeats[0], live.last_length)?;
            }
            Ok(())
        }
        _ => {
            let record = tape.records[*records];
            *records += 1;
            filters.push_outlined(record.resolve(window.produced()))
        }
    }
}

/// The index of `op` in `ops`, from its address: the walk keeps no counter.
#[cfg(feature = "parallel")]
#[inline(always)]
pub(super) fn index_of(ops: &[TapeOp], op: &TapeOp) -> usize {
    (op as *const TapeOp as usize - ops.as_ptr() as usize) / std::mem::size_of::<TapeOp>()
}

/// Set `state` (the state the tape found) to the one the shipped walk
/// leaves after the ops before `op`, or through it where `through`: for a
/// stop or an error part way, never on the tape's own end.
#[cfg(feature = "parallel")]
#[cold]
#[inline(never)]
pub(super) fn replay_to(ops: &[TapeOp], op: &TapeOp, through: bool, state: &mut MatchState) {
    let at = index_of(ops, op) + usize::from(through);
    replay_ops(&ops[..at], state);
}

/// The shipped walk's state updates over `ops` of a resolved tape. A `REP`
/// kept as decoded that meets a zero slot is the fault the walk raises
/// there, and moves nothing, as `MatchState::rotate` does.
#[cfg(feature = "parallel")]
pub(super) fn replay_ops(ops: &[TapeOp], state: &mut MatchState) {
    for op in ops {
        match op.kind() {
            tape_kind::MATCH => {
                let length = op.length();
                match op.kind_length >> WAS_SHIFT & 7 {
                    0 => state.fresh(op.distance as usize, length),
                    WAS_REP_LAST => {}
                    was => {
                        let moved = state.rotate(was as usize - 1, length);
                        debug_assert_eq!(moved.ok(), Some(op.distance as usize));
                    }
                }
            }
            tape_kind::REP => {
                let _ = state.rotate(op.distance as usize, op.length());
            }
            _ => {}
        }
    }
}

/// One far-copy prefetch hint: `Window::prefetch_source` and, in this
/// crate's own unit tests only, a record of the ring index it named, so a
/// test can compare the list's hints with the pass's ([`take_hints`]).
/// Every other build compiles the call alone.
#[inline(always)]
pub(super) fn hint(window: &Window, ahead: usize, distance: usize) {
    #[cfg(test)]
    HINTS.with(|h| {
        if let Some(h) = h.borrow_mut().as_mut() {
            h.push((distance, window.source_index(ahead, distance)));
        }
    });
    window.prefetch_source(ahead, distance);
}

/// One hint of the far list's walk ([`Window::prefetch_back`]), recorded
/// as [`hint`] records its own, `(back, ring index)`, in this crate's unit
/// tests only.
#[inline(always)]
pub(super) fn hint_back(window: &Window, anchor: usize, back: u32) {
    let _idx = window.prefetch_back(anchor, back);
    #[cfg(test)]
    HINTS.with(|h| {
        if let Some(h) = h.borrow_mut().as_mut() {
            h.push((back as usize, _idx));
        }
    });
}

#[cfg(test)]
thread_local! {
    pub(super) static HINTS: std::cell::RefCell<Option<Vec<(usize, usize)>>> =
        const { std::cell::RefCell::new(None) };
}

/// Start recording this thread's hints (`true`), or stop (`false`), and
/// answer what was recorded: `(distance, ring index)` in hint order.
#[cfg(test)]
pub(crate) fn take_hints(record: bool) -> Vec<(usize, usize)> {
    HINTS.with(|h| {
        let mut h = h.borrow_mut();
        let was = h.take().unwrap_or_default();
        if record {
            *h = Some(Vec::new());
        }
        was
    })
}

/// An operation's PREFIX with every check in place: a tape's literal run
/// is one op however long it is, so the burst is cut to the drain cadence
/// rather than to an operation, and the ring never laps what has not left
/// it. The operation itself follows it, after the last cut's drain.
#[inline(always)]
pub(super) fn checked_prefix<S: LzSink>(
    tape: &BlockTape,
    prefix: usize,
    literals: &mut usize,
    window: &mut Window,
    filters: &mut Filters,
    sink: &mut S,
) -> Result<()> {
    let mut run = &tape.verbatim[*literals..*literals + prefix];
    *literals += prefix;
    while !run.is_empty() {
        let take = run.len().min(window.drain_batch());
        window.literals(&run[..take]);
        run = &run[take..];
        if window.drain_due() {
            window.drain(sink, filters, false)?;
        }
    }
    Ok(())
}
