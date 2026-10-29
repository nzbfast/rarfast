//! The apply: a block's tape walked into the window, by pieces, with the
//! far list beside it.

use super::*;

/// The walk pieces that ship, and every arm of `h2-apply-arms` walks with.
#[cfg_attr(
    all(feature = "h2-sequence-op-knob", not(feature = "h2-apply-arms")),
    allow(dead_code)
)]
pub(super) const SHIPPED_WALK: u8 = seq::SHIPPED & seq::WALK;

/// Call `$call` with `$P` a CONSTANT, the walk pieces of `$pieces`
/// ([`seq::WALK`]). Without `h2-sequence-op-knob` the pieces are a
/// constant themselves and this is the one call; with it, one call a piece
/// set, chosen once a tape.
macro_rules! by_pieces {
    ($pieces:expr, $P:ident => $call:expr) => {{
        #[cfg(not(feature = "h2-sequence-op-knob"))]
        {
            let _ = $pieces;
            const $P: u8 = SHIPPED_WALK;
            $call
        }
        #[cfg(feature = "h2-sequence-op-knob")]
        {
            match $pieces & seq::WALK {
                0 => {
                    const $P: u8 = 0;
                    $call
                }
                2 => {
                    const $P: u8 = 2;
                    $call
                }
                4 => {
                    const $P: u8 = 4;
                    $call
                }
                6 => {
                    const $P: u8 = 6;
                    $call
                }
                8 => {
                    const $P: u8 = 8;
                    $call
                }
                10 => {
                    const $P: u8 = 10;
                    $call
                }
                12 => {
                    const $P: u8 = 12;
                    $call
                }
                _ => {
                    const $P: u8 = 14;
                    $call
                }
            }
        }
    }};
}

/// Write the tape's far list ([`BlockTape::far`]) when the far prefetch's
/// gate admits the tape ([`far_gate_admits`], the walk's own test) and it
/// holds at most [`FAR_LIST_CAP`] operations; otherwise leave it
/// incomplete. The list itself is [`fill_far_list`]'s. Out of line, so the
/// decoder it follows compiles as it did before the list.
#[inline(never)]
pub(crate) fn build_far_list(tape: &mut BlockTape) {
    // THE REFUSAL FIRST, and it allocates nothing: most tapes of most rows
    // are refused by the gate, and a member of a small solid set is one
    // tape, so a box made for every tape is paid per member (the declined
    // form's `rar5_small_solid_20k_vsnull` read +9 percent instructions,
    // an Apple M3 Mac, 24 Sep 2026).
    if tape.far_off
        || tape.steps.len() < FAR_LIST_MIN_OPS
        || tape.steps.len() > FAR_LIST_CAP
        || !far_gate_admits(&tape.steps)
    {
        if let Some(far) = tape.far.as_mut() {
            far.complete = false;
        }
        return;
    }
    let far = tape.far.get_or_insert_with(Box::default);
    fill_far_list(&tape.steps, lane_chunk(), far);
}

/// The chunk the lane writes the stream's backs for: the prefetch depth,
/// which only the measuring arms can change.
#[inline(always)]
pub(super) fn lane_chunk() -> usize {
    #[cfg(feature = "h2-apply-arms")]
    let depth = crate::probe::far_prefetch();
    #[cfg(not(feature = "h2-apply-arms"))]
    let depth = Window::FAR_PREFETCH_DEPTH;
    depth
}

/// Write `ops`' compact hint stream into `far` for chunks of `chunk`
/// operations, whatever the gate says (the gate is [`build_far_list`]'s):
/// every far match's BACK ([`FarList::backs`]) and each chunk's start
/// ([`FarList::starts`]). BRANCH FREE over the operations: every
/// operation's back is written into the next free slot, and the slot moves
/// on only for a far match, by a count and not a jump, so a stream whose
/// far and near matches interleave costs no misprediction and needs no
/// counting pass first. Only a fresh match carries a distance this large
/// (a repeat's names its slot, 0 to 3, and the rest carry 0). A zero
/// `chunk` leaves the list incomplete.
pub(crate) fn fill_far_list(ops: &[TapeOp], chunk: usize, far: &mut FarList) {
    far.complete = false;
    if chunk == 0 {
        return;
    }
    // One slot an operation at most, the buffer grown and never cleared.
    // The tape length from the start of the chunk before the current one
    // is an operation's AHEAD; it restarts from the current chunk's own
    // length at each chunk boundary. Two chunks of a tape the gate admits
    // span a few hundred bytes, far under any far distance; a back that
    // would go below zero wraps, and the walk then names no byte of the
    // ring and hints nothing for it (`Window::prefetch_back`).
    if far.backs.len() < ops.len() {
        far.backs.resize(ops.len(), 0);
    }
    let slots = &mut far.backs[..ops.len()];
    far.starts.clear();
    let mut used = 0usize;
    let mut this_chunk = 0u32;
    let distance = Window::far_distance();
    for run in ops.chunks(chunk) {
        far.starts.push(used as u32);
        let mut ahead = this_chunk;
        this_chunk = 0;
        for op in run {
            // The copy starts after the operation's own prefix.
            slots[used] = op
                .distance
                .wrapping_sub(ahead.wrapping_add(op.prefix() as u32));
            used += usize::from(op.distance as usize >= distance);
            let bytes = op.bytes() as u32;
            ahead = ahead.wrapping_add(bytes);
            this_chunk = this_chunk.wrapping_add(bytes);
        }
    }
    far.starts.push(used as u32);
    far.len = used;
    far.chunk = chunk;
    far.complete = true;
}

/// The far-copy prefetch's GATE (`Window::FAR_GATE_SAMPLE`), the same test
/// [`apply_walk`] makes inline, so the decode lane writes a list for
/// exactly the tapes the walk would hint. A copy rather than a call from
/// the walk, which keeps its own inline form untouched.
pub(crate) fn far_gate_admits(ops: &[TapeOp]) -> bool {
    let sample = &ops[..ops.len().min(Window::FAR_GATE_SAMPLE)];
    let distance = Window::far_distance();
    let far: usize = sample
        .iter()
        .map(|op| usize::from(op.kind() == tape_kind::MATCH && op.distance as usize >= distance))
        .sum();
    let bytes: usize = sample.iter().map(|op| op.bytes()).sum();
    far * Window::far_every() >= sample.len()
        && bytes <= sample.len() * Window::FAR_GATE_BYTES_PER_OP
}

/// The tape's far list when the apply stage should walk it with
/// [`apply_listed`]: the list is whole and the list form is on. `None`
/// sends the tape to [`apply`], which is the control's walk byte for byte.
///
/// Shipped, "on" is [`FAR_LIST`]. With [`LIST_KNOB`] it is the measuring
/// knob ([`far_list_knob`]); and with `h2-apply-arms` the listed walk also
/// steps aside for every other arm and dial the shipped walk honours (an
/// ablation arm, the literal ladder, a prefetch depth of zero, a pass mode
/// other than the gated one), so no measurement of [`apply_walk`] is ever
/// taken on the listed walk instead.
#[inline(always)]
pub(crate) fn listed(tape: &BlockTape) -> Option<&FarList> {
    #[cfg(any(feature = "h2-apply-arms", feature = "h2-far-list-knob"))]
    if !far_list_knob() {
        return None;
    }
    #[cfg(feature = "h2-apply-arms")]
    if crate::probe::apply_arm() != crate::probe::apply_arms::SHIPPED
        || crate::probe::literal_ladder()
        || crate::probe::far_prefetch() == 0
        || crate::probe::far_prefetch_mode() != crate::probe::far_prefetch_modes::ALL
    {
        return None;
    }
    #[cfg(not(any(feature = "h2-apply-arms", feature = "h2-far-list-knob")))]
    if !FAR_LIST {
        return None;
    }
    let far = tape.far.as_deref().filter(|far| far.complete)?;
    // A list written for another depth than the walk's: only the measuring
    // arms can make the two differ (a dial set on one thread and read on
    // another), and then the tape is walked as main walks it.
    #[cfg(feature = "h2-apply-arms")]
    if far.chunk != crate::probe::far_prefetch() {
        return None;
    }
    Some(far)
}

/// THE LIST KNOB, a measuring arm behind `h2-far-list-knob` or
/// `h2-apply-arms` (never `test-support`, which the benchmark binary turns
/// on): this thread's
/// [`crate::probe::set_far_list`] dial, else `RARKIT_FAR_LIST` read ONCE a
/// process (`1` on, anything else off, said once on stderr so a timed run
/// can show the knob reached the binary), else the shipped [`FAR_LIST`].
#[cfg(any(feature = "h2-apply-arms", feature = "h2-far-list-knob"))]
pub(super) fn far_list_knob() -> bool {
    if let Some(on) = crate::probe::far_list() {
        return on;
    }
    static FROM_ENV: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
    FROM_ENV
        .get_or_init(|| {
            let v = std::env::var_os("RARKIT_FAR_LIST")?;
            let on = v == "1";
            eprintln!("rarkit far list: {}", if on { "on" } else { "off" });
            Some(on)
        })
        .unwrap_or(FAR_LIST)
}

/// Apply one tape to the window, in archive order.
///
/// With `h2-apply-arms` this dispatches ONCE per tape on
/// `probe::apply_arms`, into a separately monomorphised walk per arm.
/// The dispatch is outside the operation loop on purpose: an arm test
/// inside it would put a compare on every one of the 12.7 million
/// operations `rar5_incompressible_64m` walks, which is the same order
/// as the costs the arms exist to measure. The shipped arm's loop is
/// the same instructions with the dial compiled in or out.
// THE SHIPPED SHAPE IS PINNED TO THE ONE IT HAD BEFORE THE ARMS.
//
// Splitting the walk out of `apply` is free only if the compiler puts
// it back. With `apply_walk` marked `inline(always)` it does, and then
// `apply` itself becomes small enough to be inlined into `apply_one`,
// which it never was before: `tape::apply` is an out-of-line symbol in
// every binary built from this package until now, twelve of them in
// `two_arm`, one per sink. That is a LAYOUT change, and layout is the
// thing that cost this work a timed measurement, so it is removed rather than
// argued about. With both attributes the tip's bench binary carries
// the same twelve `tape::apply` symbols the control's does.
#[cfg_attr(not(feature = "h2-apply-arms"), inline(never))]
pub(crate) fn apply<S: LzSink>(
    tape: &BlockTape,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut S,
) -> Result<TapeApplied> {
    filters.offload = filters::offload_wanted();
    #[cfg(feature = "h2-apply-arms")]
    {
        use crate::probe::apply_arms as arms;
        match crate::probe::apply_arm() {
            arms::NO_FRESH => apply_walk::<S, { arms::NO_FRESH }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
            arms::NO_RANGE => apply_walk::<S, { arms::NO_RANGE }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
            arms::NO_MATCH_COPY => apply_walk::<S, { arms::NO_MATCH_COPY }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
            arms::NO_LIT_STORE => apply_walk::<S, { arms::NO_LIT_STORE }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
            arms::NO_STORES => apply_walk::<S, { arms::NO_STORES }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
            arms::NEAR_SOURCE => apply_walk::<S, { arms::NEAR_SOURCE }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
            arms::WRAP_STRIDE => apply_walk::<S, { arms::WRAP_STRIDE }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
            _ => apply_walk::<S, { arms::SHIPPED }, SHIPPED_WALK>(
                tape, state, window, filters, unpacked, sink,
            ),
        }
    }
    #[cfg(not(feature = "h2-apply-arms"))]
    by_pieces!(seq_on(), P => apply_walk::<S, 0, P>(tape, state, window, filters, unpacked, sink))
}

/// THE REPEATS IN REGISTERS (piece [`seq::REGS`]): the four repeated
/// distances and the last length as five scalars of the walk, loaded from
/// the match state once a tape and put back once a tape, before any
/// checked operation (which reads the state) and on every way out. A fresh
/// match moves four registers; a repeat picks its slot by selects, as the
/// lane's [`Ring`] does, where the shipped walk stores five words a fresh
/// match and calls [`MatchState::rotate_outlined`] a repeat.
#[derive(Clone, Copy)]
pub(super) struct Regs {
    pub(super) r0: usize,
    pub(super) r1: usize,
    pub(super) r2: usize,
    pub(super) r3: usize,
    pub(super) last: usize,
}

impl Regs {
    #[inline(always)]
    pub(super) fn of(state: &MatchState) -> Regs {
        let [r0, r1, r2, r3] = state.repeats;
        Regs {
            r0,
            r1,
            r2,
            r3,
            last: state.last_length,
        }
    }

    #[inline(always)]
    pub(super) fn put(self, state: &mut MatchState) {
        state.repeats = [self.r0, self.r1, self.r2, self.r3];
        state.last_length = self.last;
    }

    /// `MatchState::fresh`.
    #[inline(always)]
    pub(super) fn fresh(&mut self, distance: usize, length: usize) {
        self.r3 = self.r2;
        self.r2 = self.r1;
        self.r1 = self.r0;
        self.r0 = distance;
        self.last = length;
    }

    /// `MatchState::rotate_outlined`: the distance of slot `k` (at most
    /// 3) moved to the front, or 0 for an unset slot with nothing moved.
    #[inline(always)]
    pub(super) fn take(&mut self, k: usize, length: usize) -> usize {
        use core::hint::select_unpredictable as pick;
        let even = k & 1 == 0;
        let low = pick(even, self.r0, self.r1);
        let high = pick(even, self.r2, self.r3);
        let chosen = pick(k < 2, low, high);
        if chosen == 0 {
            return 0;
        }
        self.r3 = pick(k >= 3, self.r2, self.r3);
        self.r2 = pick(k >= 2, self.r1, self.r2);
        self.r1 = pick(k >= 1, self.r0, self.r1);
        self.r0 = chosen;
        self.last = length;
        chosen
    }
}

/// THE OPERATION LOOP of [`apply_walk`] and [`apply_listed`] over one chunk
/// of `run`, the sequence op's:
/// each operation's PREFIX is
/// copied whatever its length, zero included, and then the operation, so
/// the loop carries no `LITS` against `MATCH` dispatch, and an operation
/// that could reach the drain, or whose own length is the live state's,
/// takes [`apply_checked`]. `P` are the walk pieces ([`seq::WALK`]);
/// `trusted` is the lane's reach admitted for this tape ([`note_reach`]),
/// which with [`seq::TRUST`] drops a fresh match's range tests. `ARM` and
/// `ladder` are `h2-apply-arms`' and fold away without it.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn walk_run<S: LzSink, const ARM: u8, const P: u8, const SITE: u8>(
    tape: &BlockTape,
    run: &[TapeOp],
    literals: &mut usize,
    records: &mut usize,
    budget: &mut usize,
    regs: &mut Regs,
    trusted: bool,
    ladder: bool,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    let in_regs = P & seq::REGS != 0;
    let _ = ladder;
    for op in run {
        let prefix = op.prefix();
        let length = op.length();
        let kind = op.kind();
        let bytes = prefix + length;
        // A decoded `MATCH` or `REP` is two bytes or more and a `LITS` one
        // or more, so a zero budget is always over; an operation of no
        // bytes (only a hand-built tape has one) moves nothing on the fast
        // path either.
        if bytes > *budget || kind >= tape_kind::REP_LAST {
            if in_regs {
                regs.put(state);
            }
            if window.drain_due() {
                window.drain(sink, filters, false)?;
            }
            apply_checked::<S, SITE>(
                tape, *op, literals, records, state, window, filters, unpacked, sink,
            )?;
            if in_regs {
                *regs = Regs::of(state);
            }
            *budget = window.apply_budget();
            continue;
        }
        // THE PREFIX AND THE OPERATION. The whole of what is left of the
        // literals, not the run's slice: the tape pads its literal buffer
        // by `STRIDE_MAX`, which is what the fixed-width writes need and
        // what a slice cut to `prefix` would throw away.
        let lits = &tape.verbatim[*literals..];
        *literals += prefix;
        // The measuring arms keep the two halves apart, as they measured
        // them; every build that ships takes `Window::sequence`.
        #[cfg(feature = "h2-apply-arms")]
        let split = ARM != crate::probe::apply_arms::SHIPPED || ladder;
        #[cfg(not(feature = "h2-apply-arms"))]
        let split = false;
        if split {
            #[cfg(feature = "h2-apply-arms")]
            {
                if ARM == crate::probe::apply_arms::NO_LIT_STORE
                    || ARM == crate::probe::apply_arms::NO_STORES
                {
                    window.skip_write(prefix);
                } else if ladder {
                    window.literals(&lits[..prefix]);
                } else {
                    window.literals_padded(lits, prefix);
                }
            }
        }
        match kind {
            tape_kind::MATCH => {
                let distance = op.distance as usize;
                #[cfg(feature = "h2-apply-arms")]
                if ARM == crate::probe::apply_arms::NO_FRESH {
                    if in_regs {
                        regs.r0 = distance;
                        regs.last = length;
                    } else {
                        state.repeats[0] = distance;
                        state.last_length = length;
                    }
                } else if in_regs {
                    regs.fresh(distance, length);
                } else {
                    state.fresh(distance, length);
                }
                #[cfg(not(feature = "h2-apply-arms"))]
                if in_regs {
                    regs.fresh(distance, length);
                } else {
                    state.fresh(distance, length);
                }
                let copied = if split {
                    copy_piece::<ARM, P>(window, distance, length, trusted)
                } else {
                    sequence_piece::<P>(window, lits, prefix, distance, length, trusted)
                };
                if let Err(err) = copied {
                    if in_regs {
                        regs.put(state);
                    }
                    return Err(err);
                }
            }
            tape_kind::REP => {
                let k = op.distance as usize;
                let distance = if in_regs {
                    regs.take(k, length)
                } else {
                    state.rotate_outlined(k, length)
                };
                if distance == 0 {
                    // The prefix is output before the repeat fails.
                    if !split {
                        window.literals_padded(lits, prefix);
                    }
                    if in_regs {
                        regs.put(state);
                    }
                    return Err(fault::uninitialised_repeat());
                }
                // A repeat keeps the range tests: its distance is the live
                // state's, which the lane never saw.
                let copied = if split {
                    copy_piece::<ARM, P>(window, distance, length, false)
                } else {
                    sequence_piece::<P>(window, lits, prefix, distance, length, false)
                };
                if let Err(err) = copied {
                    if in_regs {
                        regs.put(state);
                    }
                    return Err(err);
                }
            }
            _ => {
                if !split {
                    window.literals_padded(lits, prefix);
                }
            }
        }
        *budget -= bytes;
    }
    Ok(())
}

/// [`Window::sequence`] under the walk pieces `P`, as [`copy_piece`]
/// chooses the copy.
#[inline(always)]
pub(super) fn sequence_piece<const P: u8>(
    window: &mut Window,
    lits: &[u8],
    prefix: usize,
    distance: usize,
    length: usize,
    trusted: bool,
) -> Result<()> {
    let trusted = P & seq::TRUST != 0 && trusted;
    match (trusted, P & seq::WIDE != 0) {
        (true, true) => window.sequence::<true, true>(lits, prefix, distance, length),
        (true, false) => window.sequence::<true, false>(lits, prefix, distance, length),
        (false, true) => window.sequence::<false, true>(lits, prefix, distance, length),
        (false, false) => window.sequence::<false, false>(lits, prefix, distance, length),
    }
}

/// A match copy under the walk pieces `P`: with [`seq::TRUST`] and a
/// `trusted` tape, no range test; with [`seq::WIDE`], the whole-source
/// copy. Every other arm of `h2-apply-arms` is its own copy
/// ([`copy_match_arm`]).
#[inline(always)]
pub(super) fn copy_piece<const ARM: u8, const P: u8>(
    window: &mut Window,
    distance: usize,
    length: usize,
    trusted: bool,
) -> Result<()> {
    #[cfg(feature = "h2-apply-arms")]
    if ARM != crate::probe::apply_arms::SHIPPED {
        return copy_match_arm::<ARM>(window, distance, length);
    }
    let trusted = P & seq::TRUST != 0 && trusted;
    match (trusted, P & seq::WIDE != 0) {
        (true, true) => window.copy_match_in::<true, true>(distance, length),
        (true, false) => window.copy_match_in::<true, false>(distance, length),
        (false, true) => window.copy_match_in::<false, true>(distance, length),
        (false, false) => window.copy_match_in::<false, false>(distance, length),
    }
}

/// The walk itself. `ARM` is `probe::apply_arms::SHIPPED` in every build
/// that ships; the other arms exist only with `h2-apply-arms` and every
/// test of them folds away without it.
///
/// `inline(always)` WHEN THE ARMS ARE OFF, which is every shipped build
/// and every bench binary. There is then exactly one call site and the
/// point of splitting the function out is gone, so this guarantees the
/// walk keeps the shape it had before the arms existed rather than
/// leaving it to the inliner's judgement. With the arms on there are
/// several call sites and inlining them all would be the bloat that
/// cost this work a timed measurement.
#[cfg_attr(
    not(any(feature = "h2-apply-arms", feature = "h2-sequence-op-knob")),
    inline(always)
)]
pub(super) fn apply_walk<S: LzSink, const ARM: u8, const P: u8>(
    tape: &BlockTape,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut S,
) -> Result<TapeApplied> {
    let mut literals = 0usize;
    let mut records = 0usize;
    // HOW MANY BYTES MAY BE PRODUCED BEFORE ANYTHING NEEDS CHECKING
    // AGAIN, counted down rather than recomputed.
    //
    // The checked path below is the whole of this loop as it used to be,
    // and it is still what runs whenever the answer could be no. What
    // changed is that it no longer runs for EVERY operation: the drain
    // cadence is a distance in bytes, and an operation shorter than it
    // cannot reach it. So the distance is asked for once and decremented,
    // and the fast arms below drop the recomputation of `produced()` and
    // the drain test per operation. (Until SPEC-H2's change of 28 Sep 2026
    // the budget also counted down to the member's declared end, where the
    // walk stopped and clamped the crossing operation; a member now
    // applies every operation it owns and the drain caps its output.) That is worth doing because this stage is
    // the critical path (SPEC-H2 7.3 item 1) and it is bound by
    // OPERATIONS: 7.8 million on `rar5_text_64m_m3` and 12.7 million on
    // `rar5_incompressible_64m`, 5 to 9 output bytes each.
    //
    // Nothing observable moves. The budget is at most the bytes left before
    // the next drain, so the ring cannot lap what has not left it and the
    // literal chunking the drain cadence used to impose is satisfied by
    // construction. A budget of zero, an operation longer than the
    // budget, and the two kinds whose length is not in the operation
    // (`REP_LAST` takes the last match's length, `FILTER` produces
    // nothing) all fall to the checked path, which recomputes the budget
    // when it is done.
    // THE LITERAL ARM, read ONCE for the block rather than per operation.
    // Without `h2-apply-arms` it is a constant and the ladder arm below
    // folds away entirely, so a shipped build carries neither the read
    // nor the branch. See `probe::LITERAL_LADDER` for why the two arms
    // live in one binary at all.
    #[cfg(feature = "h2-apply-arms")]
    let ladder = crate::probe::literal_ladder();
    #[cfg(not(feature = "h2-apply-arms"))]
    let ladder = false;
    // THE ABLATION ARM THAT CUTS THE REPEAT WRITE CANNOT BE ALLOWED TO
    // ERROR. It leaves slots the shipped walk would have set, and an
    // unset slot is `UninitialisedRepeat`, which ends the member early
    // and reads as a saving worth everything it skipped. Seeded once per
    // tape, not per operation, so it costs nothing the table can see.
    #[cfg(feature = "h2-apply-arms")]
    if ARM == crate::probe::apply_arms::NO_FRESH {
        for slot in state.repeats.iter_mut() {
            if *slot == 0 {
                *slot = 1;
            }
        }
    }
    // THE FAR-COPY PREFETCH, its depth read ONCE for the tape.
    // The walk runs in CHUNKS of `depth` operations, and before each chunk
    // a separate short pass hints the source of every FRESH match in the
    // NEXT chunk: its distance is in the tape already, and its write point
    // is this one plus the lengths between them, which `lead` (the current
    // chunk's total length) and the pass's own running sum give. A hint
    // moves no byte and raises nothing (`Window::prefetch_source`), so an
    // estimate a `REP_LAST` or a filter record throws off costs a line of
    // bandwidth and no more. Repeats are not hinted: their distance is the
    // live state's, which the fresh matches between rotate.
    //
    // WHY A SEPARATE PASS AND NOT A LOOKAHEAD IN THE LOOP. The first form
    // carried the lookahead inside the per-operation loop, and on an Apple M3 Mac
    // (23 Sep 2026) that bookkeeping alone cost `code_32m_m3` and `md128k`
    // 16 to 22 percent of the apply stage with almost no hint issued, and a
    // test on the distance cost `text_64m_m3` its whole gain. The pass
    // keeps the operation loop below exactly the shipped one.
    #[cfg(feature = "h2-apply-arms")]
    let (depth, mode) = (
        crate::probe::far_prefetch(),
        crate::probe::far_prefetch_mode(),
    );
    #[cfg(not(feature = "h2-apply-arms"))]
    let depth = Window::FAR_PREFETCH_DEPTH;
    // A stream whose ring the cache holds whole is never hinted
    // (`Window::FAR_DICTIONARY_FLOOR`), asked once a tape.
    let depth = if window.far_off() { 0 } else { depth };
    let ops = &tape.steps[..];
    // THE GATE (`Window::FAR_GATE_SAMPLE`): a tape whose sampled matches
    // reach far back often enough is hinted, and any other runs exactly
    // the shipped walk. Counted, not branched on, per sampled operation.
    #[cfg(feature = "h2-apply-arms")]
    let gated = mode == crate::probe::far_prefetch_modes::ALL;
    #[cfg(not(feature = "h2-apply-arms"))]
    let gated = true;
    let depth = if depth != 0 && gated {
        let sample = &ops[..ops.len().min(Window::FAR_GATE_SAMPLE)];
        let distance = Window::far_distance();
        let far: usize = sample
            .iter()
            .map(|op| {
                usize::from(op.kind() == tape_kind::MATCH && op.distance as usize >= distance)
            })
            .sum();
        let bytes: usize = sample.iter().map(|op| op.bytes()).sum();
        if far * Window::far_every() >= sample.len()
            && bytes <= sample.len() * Window::FAR_GATE_BYTES_PER_OP
        {
            depth
        } else {
            0
        }
    } else {
        depth
    };
    let chunk = if depth == 0 { ops.len().max(1) } else { depth };
    let mut lead: usize = if depth == 0 {
        0
    } else {
        ops.iter().take(chunk).map(|op| op.bytes()).sum()
    };
    let mut budget = window.apply_budget();
    // THE REPEATS IN REGISTERS (piece `REGS`), after the arms' seeding
    // above, and the lane's reach asked once a tape (piece `TRUST`).
    let mut regs = Regs::of(state);
    let trusted = tape.reach.is_some_and(|reach| window.admits_reach(reach));
    for (group, run) in ops.chunks(chunk).enumerate() {
        if depth != 0 {
            let from = (group + 1) * chunk;
            let next = ops
                .get(from..)
                .map_or(&[][..], |rest| &rest[..rest.len().min(chunk)]);
            let mut offset = lead;
            // BRANCH FREE: every operation is hinted, a fresh match at its
            // source and anything else at its own write point (distance
            // zero, a line the walk is about to write anyway), so the pass
            // carries no data-dependent jump to mispredict or to scramble
            // the branch history the operation loop below predicts with.
            // A MASK and not an `if`: LLVM lowered the `if` form to a jump
            // around the distance's load, the very branch this pass exists
            // not to have (read in the linked binary, 23 Sep 2026).
            let pick = |op: &TapeOp| {
                let is_match = usize::from(op.kind() == tape_kind::MATCH);
                op.distance as usize & is_match.wrapping_neg()
            };
            #[cfg(feature = "h2-apply-arms")]
            let dry = mode == crate::probe::far_prefetch_modes::DRY;
            #[cfg(not(feature = "h2-apply-arms"))]
            let dry = false;
            // An operation's copy starts after its prefix.
            if dry {
                for ahead in next {
                    std::hint::black_box(window.source_index(offset + ahead.prefix(), pick(ahead)));
                    offset += ahead.bytes();
                }
            } else {
                for ahead in next {
                    hint(window, offset + ahead.prefix(), pick(ahead));
                    offset += ahead.bytes();
                }
            }
            lead = offset - lead;
        }
        walk_run::<S, ARM, P, 0>(
            tape,
            run,
            &mut literals,
            &mut records,
            &mut budget,
            &mut regs,
            trusted,
            ladder,
            state,
            window,
            filters,
            unpacked,
            sink,
        )?;
    }
    if P & seq::REGS != 0 {
        regs.put(state);
    }
    Ok(TapeApplied::BlockDone)
}

/// Apply one tape that carries a whole FAR LIST ([`listed`]), in archive
/// order: [`apply_walk`]'s shipped walk exactly, with the far-copy
/// prefetch's hints taken from the list instead of from a pass over every
/// operation.
///
/// **WHY A SECOND FUNCTION AND NOT A BRANCH IN [`apply`].** The declined
/// far list moved the pass out of line for every tape and paid 1.5 to 3
/// percent on rows the list never reaches, the shape and not the work
/// (23 Sep 2026). Here [`apply`] and [`apply_walk`] are
/// the control's source, and the apply stage chooses between the two walks once
/// a tape, outside both. So a tape without a list runs the control's code, and
/// only a listed tape pays for whatever shape this function has.
///
/// **THE HINTS.** Before chunk `g` of `depth` operations is applied, every
/// far match of chunk `g + 1` is hinted at the write point less its back
/// ([`Window::prefetch_back`], [`FarList::backs`]): its back is its
/// distance less the tape length from chunk `g`'s start to it, so the
/// address is exactly the one the pass gives that operation. Chunk 0 is
/// never hinted, as in the pass. A hint moves no byte and raises nothing.
/// The compact hint stream ([`FarList`]): the lane did the arithmetic and
/// kept the far matches alone, so a hint is a load, a subtract, one wrap
/// and the prefetch, and a chunk's bookkeeping is two starts.
///
/// **THE OPERATION LOOP** below is [`apply_walk`]'s for the shipped arm,
/// line for line; `the_far_list_hints_what_the_pass_hints_for_every_far_match`
/// holds the two walks to the same bytes, drain pieces, repeat state and
/// stop or error over random tapes of every kind.
///
/// **ONE INSTANCE, NOT ONE PER SINK.** The sink arrives as `dyn`: the walk
/// reaches it only when it drains, once a batch, so a virtual call there
/// costs nothing a row can see. Generic over the sink, this walk was
/// compiled beside every `tape::apply<S>` in every crate that names a
/// sink, and the shipped CLI's six own instances of `tape::apply` came out
/// in another shape than the control's (1,646 instructions against 1,674, the
/// same calls, by census on an Apple M3 Mac, 24 Sep 2026); as one function in
/// this crate it is compiled once, beside none of them.
#[inline(never)]
pub(crate) fn apply_listed(
    tape: &BlockTape,
    far: &FarList,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut dyn LzSink,
) -> Result<TapeApplied> {
    by_pieces!(seq_on(), P => listed_walk::<P>(tape, far, state, window, filters, unpacked, sink))
}

/// [`apply_listed`]'s walk for the sequence op's walk pieces `P`
/// ([`seq::WALK`]): inlined into it where only the shipped pieces exist,
/// one instance a piece set out of line in a knob build.
#[cfg_attr(not(feature = "h2-sequence-op-knob"), inline(always))]
#[cfg_attr(feature = "h2-sequence-op-knob", inline(never))]
pub(super) fn listed_walk<const P: u8>(
    tape: &BlockTape,
    far: &FarList,
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
    // The list's own chunk, never zero on a whole list; `max` so a list
    // that broke that could not stop the walk.
    let chunk = far.chunk.max(1);
    let backs = &far.backs[..far.len];
    let mut budget = window.apply_budget();
    let mut regs = Regs::of(state);
    let trusted = tape.reach.is_some_and(|reach| window.admits_reach(reach));
    for (group, run) in ops.chunks(chunk).enumerate() {
        // The next chunk's far matches, one slice a chunk, nothing after
        // the last.
        if let Some(&[from, to]) = far.starts.get(group + 1..group + 3) {
            let anchor = window.hint_anchor();
            for &back in &backs[from as usize..to as usize] {
                hint_back(window, anchor, back);
            }
        }
        walk_run::<DynSink<'_>, 0, P, 1>(
            tape,
            run,
            &mut literals,
            &mut records,
            &mut budget,
            &mut regs,
            trusted,
            false,
            state,
            window,
            filters,
            unpacked,
            sink,
        )?;
    }
    if P & seq::REGS != 0 {
        regs.put(state);
    }
    Ok(TapeApplied::BlockDone)
}

/// One tape by the walk pieces `pieces` ([`seq::WALK`]), whatever this
/// build ships: [`apply_walk`]'s walk, or with `far` [`apply_listed`]'s,
/// for the tests that hold every piece set to the plain walk.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_pieces<S: LzSink>(
    pieces: u8,
    far: Option<&FarList>,
    tape: &BlockTape,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut S,
) -> Result<TapeApplied> {
    macro_rules! with {
        ($P:literal) => {
            match far {
                Some(far) => listed_walk::<$P>(tape, far, state, window, filters, unpacked, sink),
                None => apply_walk::<S, 0, $P>(tape, state, window, filters, unpacked, sink),
            }
        };
    }
    match pieces & seq::WALK {
        0 => with!(0),
        2 => with!(2),
        4 => with!(4),
        6 => with!(6),
        8 => with!(8),
        10 => with!(10),
        12 => with!(12),
        _ => with!(14),
    }
}

/// Any sink, as [`apply_listed`] drains into it: one virtual call a drain.
pub(super) struct DynSink<'a>(pub(super) &'a mut dyn LzSink);

impl LzSink for DynSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.put(bytes)
    }
}

/// The match copy for one arm of [`apply_walk`] other than the shipped
/// one ([`copy_piece`] takes that).
#[cfg(feature = "h2-apply-arms")]
#[inline(always)]
pub(super) fn copy_match_arm<const ARM: u8>(
    window: &mut Window,
    distance: usize,
    length: usize,
) -> Result<()> {
    if ARM == crate::probe::apply_arms::SHIPPED {
        return window.copy_match(distance, length);
    }
    window.copy_match_ablated::<ARM>(distance, length)
}

/// One operation with every check in place, which is what this loop used
/// to do for all of them. The fast arms in [`apply`] are this function
/// with the checks its caller has already answered removed; nothing here
/// may differ from them in anything but speed.
///
/// `SITE` names the ONE walk that calls this instance: 0 for
/// [`apply_walk`], 1 for [`apply_listed`]. Each instance then has a single
/// call site, which is what lets the inliner fold it into its walk as it
/// did when [`apply_walk`] was its only caller; one instance called from
/// both walks was left out of line in both, `tape::apply` 1,674
/// instructions on main against 959 with the call (an Apple M3 Mac, 24 Sep 2026,
/// the shipped rarfast, by census).
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_checked<S: LzSink, const SITE: u8>(
    tape: &BlockTape,
    op: TapeOp,
    literals: &mut usize,
    records: &mut usize,
    state: &mut MatchState,
    window: &mut Window,
    filters: &mut Filters,
    unpacked: u64,
    sink: &mut S,
) -> Result<()> {
    let (kind, distance, length) = (op.kind(), op.distance, op.length());
    {
        let literals = &mut *literals;
        let records = &mut *records;
        checked_prefix(tape, op.prefix(), literals, window, filters, sink)?;
        match kind {
            tape_kind::LITS => {}
            tape_kind::MATCH => {
                let distance = distance as usize;
                state.fresh(distance, length);
                window.copy_match(distance, length)?;
            }
            tape_kind::REP => {
                let distance = state.rotate_outlined(distance as usize, length);
                if distance == 0 {
                    return Err(fault::uninitialised_repeat());
                }
                window.copy_match(distance, length)?;
            }
            tape_kind::REP_LAST => {
                if state.last_length != 0 {
                    let length = state.last_length;
                    window.copy_match(state.repeats[0], length)?;
                }
            }
            _ => {
                let record = tape.records[*records];
                *records += 1;
                // Out of line on purpose: see `Filters::push_outlined`.
                filters.push_outlined(record.resolve(window.produced()))?;
            }
        }
    }
    Ok(())
}
