//! The run's encoder of either family, and the windows a flush of it
//! stages.

use super::*;

// The most WINDOWS of one member a flush parses at once, which a test may
// set to 1 to get the walk this engine had before windows were staged: a
// window at a time, every window its own wave. Staging is a wave's width
// and never a member's bytes, so a member written at any depth is the
// same archive, and `tests/one_member_windows.rs` compares the bytes.
// Without `bench-internals` the depth is the constant.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static WINDOW_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    pub(super) static WIDEST_FLUSH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The most windows of one member a flush stages (see the comment above).
/// Unbounded in a shipped build: `Engine::may_stage` is what ends a batch.
pub(super) fn window_depth() -> usize {
    #[cfg(feature = "bench-internals")]
    {
        WINDOW_DEPTH.with(std::cell::Cell::get).max(1)
    }
    #[cfg(not(feature = "bench-internals"))]
    {
        usize::MAX
    }
}

/// Runs `work` with this thread's window depth set to `depth`, and puts
/// it back afterwards. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_window_depth<T>(depth: usize, work: impl FnOnce() -> T) -> T {
    let was = WINDOW_DEPTH.with(|cell| cell.replace(depth));
    let result = work();
    WINDOW_DEPTH.with(|cell| cell.set(was));
    result
}

/// The most windows one flush of a windowed member has parsed on this
/// thread since [`forget_widest_flush`]. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn widest_flush() -> usize {
    WIDEST_FLUSH.with(std::cell::Cell::get)
}

/// Starts [`widest_flush`] again from zero.
#[cfg(feature = "bench-internals")]
pub(crate) fn forget_widest_flush() {
    WIDEST_FLUSH.with(|cell| cell.set(0));
}

/// Hand one window of a member to the encoder, STAGED beside the windows
/// before it rather than parsed on its own, and flush when the batch is
/// full or the member ends, appending every staged window's packed bytes
/// to `packed` in order.
///
/// **Why a window at a time was narrow.** A window is the dictionary, 2
/// MiB at the shipped default, which is eight parse blocks, and a flush
/// is one wave that empties before the next window is read. Counted
/// untimed on 28 Sep 2026:
/// one 64 MiB text member at `-m1` ran 32 waves of eight blocks, each the
/// chain insert's 4 ms and then the wait for its last block's 7 ms parse,
/// about 4.5 wide on 16 cores where rar 7.23 ran 8.
///
/// **Why it moves no byte.** A batch of one member's windows is the batch
/// a solid set stages (`Engine::flush`), and each window is a segment of
/// it: its blocks, its walk groups and the slice its finder and parse
/// see all stop at the window's own end, exactly as they did when it was
/// the last thing in the history, and `Engine::may_stage` ends the batch
/// before anything that would move a byte, a history slide above all, so
/// every slide falls at the window it fell at before. Only the wave is
/// wider.
///
/// **What it holds.** The staged windows' input is already in the
/// encoder's history, which is the dictionary plus its slack whether or
/// not windows are staged; what staging adds is the packed bytes of the
/// windows in flight, bounded by `Engine::batch_cap`, and the hints of up
/// to [`crate::encode::drive::HINT_BUDGET_BYTES`] where the tree walks.
/// So it runs only where the caller set no memory ceiling
/// (`Run::caller_ceiling`), which is where the writer spends memory for
/// wall; under a ceiling, whose sum (`Run::beside_team_bytes`) counts one
/// window's wave, the writer keeps a window a flush.
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_window(
    encoder: &mut Encoder,
    window: &[u8],
    last: bool,
    base: u64,
    packed: &mut Vec<u8>,
    kept: bool,
    depth: usize,
    staged: &mut usize,
) {
    if *staged >= depth || (*staged > 0 && !encoder.may_stage(window.len())) {
        flush_windows(encoder, packed, kept, staged);
    }
    encoder.stage_window(window, last, base);
    *staged += 1;
    if last {
        flush_windows(encoder, packed, kept, staged);
    }
}

/// Parse the windows [`stage_window`] staged and append their packed
/// bytes to `packed`, in staging order.
///
/// `packed` itself is lent to the first window for the flush, and the
/// windows after it append to it there (`Engine::lend_first`), so the
/// batch's packed bytes are written once, into the member's buffer, and
/// come back as the first output, which goes back to `packed` whole; the
/// rest are empty. So a buffer `Run::reserve_held` reserved for the whole
/// member (`kept`) is never swapped away for another and never copied into
/// one: it comes back at the capacity it was lent at (spec G 3.5's
/// held-member rule, 30 Sep 2026: swapped away, it went to the engine, which
/// kept it beside the one the member then grew by appends, two buffers of
/// the member's size, 750 MiB for S8's 356 MB member).
pub(super) fn flush_windows(
    encoder: &mut Encoder,
    packed: &mut Vec<u8>,
    kept: bool,
    staged: &mut usize,
) {
    #[cfg(feature = "bench-internals")]
    WIDEST_FLUSH.with(|cell| cell.set(cell.get().max(*staged)));
    let lent = packed.capacity();
    encoder.lend_first(std::mem::take(packed));
    for (index, out) in encoder.flush().iter_mut().enumerate() {
        if index == 0 {
            // The member's own buffer, lent above, with this batch's bytes
            // after the ones it held.
            std::mem::swap(packed, out);
        } else {
            packed.append(out);
        }
    }
    debug_assert!(
        !kept || packed.capacity() == lent,
        "a buffer reserved for the member comes back as it was lent"
    );
    *staged = 0;
}

/// A flush of `_staged` windows ran on the pool, beside this thread's
/// reads ([`WindowsAhead`]): the writing thread's own figure for
/// `widest_flush`, which the flush wrote on the thread it ran on.
pub(super) fn note_flush_width(_staged: usize) {
    #[cfg(feature = "bench-internals")]
    WIDEST_FLUSH.with(|cell| cell.set(cell.get().max(_staged)));
}

/// Whichever encoder the target format asks for, boxed so that the two
/// do not size this function's frame between them.
///
/// **Every call that parses or judges runs on the write's pool**
/// (`width::on_pool`): the encoder's waves, walkers and the
/// filter sweep take the pool they are called from, so the writer hands
/// them one no wider than `workers`. A call from one of that pool's own
/// threads (a crew) runs where it is.
///
/// The RAR 5 arm carries spec G 3.8.2's filter plan beside the encoder:
/// `Some` under `FilterPolicy::Detect` at a compressing level, holding the
/// plan buffer each call reuses, and `None` where no filter may run.
pub(super) enum Encoder {
    Rar5(Box<rar5_encode::Rar5Encoder>, Option<Vec<FilterSpan>>),
    Rar29(Box<rar29::Rar29Encoder>),
}

impl Encoder {
    /// One region's blocks, appended. `span[..emit_from]` is history.
    ///
    /// Under `FilterPolicy::Detect` the member's bytes are judged here and
    /// the plan goes down with them (spec G 3.8.2); `span` is a whole
    /// member, so its first byte is the member's.
    pub(super) fn region(&mut self, span: &[u8], emit_from: usize, last: bool, out: &mut Vec<u8>) {
        width::on_pool(move || match self {
            Encoder::Rar5(encoder, Some(plan)) => {
                debug_assert_eq!(emit_from, 0, "a region is a whole member");
                filters::detect(&span[emit_from..], 0, plan);
                encoder.encode_region_filtered(span, emit_from, last, out, plan, 0);
            }
            Encoder::Rar5(encoder, None) => encoder.encode_region(span, emit_from, last, out),
            Encoder::Rar29(encoder) => encoder.encode_region(span, emit_from, last, out),
        })
    }

    /// The next chunk of a CARRIED run: the next window of spec G 3.7.3's
    /// windowed encode, or the next member of 3.9's solid set. The
    /// encoder holds the history and the match finder's index over it,
    /// which is what keeps a solid member from paying for the members
    /// before it (spec H3 section 4). `base` is `chunk`'s offset in its
    /// member, which a filter's transform is measured from.
    pub(super) fn chunk(&mut self, chunk: &[u8], last: bool, out: &mut Vec<u8>, base: u64) {
        width::on_pool(move || match self {
            Encoder::Rar5(encoder, Some(plan)) => {
                filters::detect(chunk, base, plan);
                encoder.encode_chunk_filtered(chunk, last, out, plan, base);
            }
            Encoder::Rar5(encoder, None) => encoder.encode_chunk(chunk, last, out),
            Encoder::Rar29(encoder) => encoder.encode_chunk(chunk, last, out),
        })
    }

    /// Whether a chunk of `chunk` bytes may join the batch already
    /// staged. `encode::drive::Engine::may_stage` has the whole rule.
    pub(super) fn may_stage(&self, chunk: usize) -> bool {
        match self {
            Encoder::Rar5(encoder, _) => encoder.may_stage(chunk),
            Encoder::Rar29(encoder) => encoder.may_stage(chunk),
        }
    }

    /// Stage one chunk of a carried run, to be parsed by the next
    /// [`Encoder::flush`] along with everything staged beside it. A
    /// staged chunk is a whole member, so its first byte is the member's.
    pub(super) fn stage(&mut self, chunk: &[u8], last: bool) {
        match self {
            // The judging is a pool sweep (`filters::detect`).
            Encoder::Rar5(encoder, Some(plan)) => width::on_pool(move || {
                filters::detect(chunk, 0, plan);
                encoder.stage_filtered(chunk, last, plan, 0);
            }),
            Encoder::Rar5(encoder, None) => encoder.stage(chunk, last),
            Encoder::Rar29(encoder) => encoder.stage(chunk, last),
        }
    }

    /// Stage the next WINDOW of one member (spec G 3.7.3), to be parsed
    /// by the next [`Encoder::flush`] with the windows staged before it.
    /// Judged and filtered as [`Encoder::chunk`] judges it, from `base`,
    /// its offset in the member.
    pub(super) fn stage_window(&mut self, window: &[u8], last: bool, base: u64) {
        match self {
            Encoder::Rar5(encoder, Some(plan)) => width::on_pool(move || {
                filters::detect(window, base, plan);
                encoder.stage_filtered(window, last, plan, base);
            }),
            Encoder::Rar5(encoder, None) => encoder.stage(window, last),
            Encoder::Rar29(encoder) => encoder.stage(window, last),
        }
    }

    /// Whether a window this encoder stages is given a filter plan
    /// (`filters::detect`) first, which is what [`plan_ahead`] can take
    /// beside a flush.
    pub(super) fn plans_filters(&self) -> bool {
        matches!(self, Encoder::Rar5(_, Some(_)))
    }

    /// [`Encoder::stage_window`] with the window's filter plan already
    /// taken (`planned`, by [`plan_ahead`] over the same bytes at the same
    /// offset), which is then not taken again; the buffer it replaces goes
    /// to `spare`. Without one, the plan is taken here as before.
    pub(super) fn stage_window_planned(
        &mut self,
        window: &[u8],
        last: bool,
        base: u64,
        planned: Option<Vec<FilterSpan>>,
        spare: &mut Vec<Vec<FilterSpan>>,
    ) {
        match (self, planned) {
            (Encoder::Rar5(encoder, Some(plan)), Some(mut ready)) => {
                std::mem::swap(plan, &mut ready);
                spare.push(ready);
                width::on_pool(move || encoder.stage_filtered(window, last, plan, base));
            }
            (this, planned) => {
                if let Some(unused) = planned {
                    spare.push(unused);
                }
                this.stage_window(window, last, base);
            }
        }
    }

    /// Lend the chunk staged last an output buffer. `Engine::lend_out`.
    pub(super) fn lend_out(&mut self, out: Vec<u8>) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.lend_out(out),
            Encoder::Rar29(encoder) => encoder.lend_out(out),
        }
    }

    /// Lend the first chunk staged a buffer to append to.
    /// `Engine::lend_first`.
    pub(super) fn lend_first(&mut self, out: Vec<u8>) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.lend_first(out),
            Encoder::Rar29(encoder) => encoder.lend_first(out),
        }
    }

    /// Parse the whole batch as one wave: the packed bytes of every
    /// staged chunk, in staging order.
    pub(super) fn flush(&mut self) -> &mut [Vec<u8>] {
        width::on_pool(move || match self {
            Encoder::Rar5(encoder, _) => encoder.flush(),
            Encoder::Rar29(encoder) => encoder.flush(),
        })
    }

    /// The carried history's slack, in dictionaries
    /// (`encode::drive::Engine::set_slack_multiple`).
    pub(super) fn set_slack_multiple(&mut self, multiple: usize) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.set_slack_multiple(multiple),
            Encoder::Rar29(encoder) => encoder.set_slack_multiple(multiple),
        }
    }

    /// End the carried run.
    pub(super) fn reset_history(&mut self) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.reset_history(),
            Encoder::Rar29(encoder) => encoder.reset_history(),
        }
    }

    /// Stand where an engine that has just slid its history stands, in
    /// the middle of a member, `kept` the dictionary the slide kept as the
    /// member's own bytes, whole windows of `window` of them, the first at
    /// `base` in the member. `Engine::resume_slid`.
    ///
    /// Under `FilterPolicy::Detect` the slid engine's history held each
    /// window as it was staged, its filter spans transformed, so each
    /// kept window is judged again here, from the same bytes and the same
    /// offset, and transformed in the resumed history (the judging is a
    /// function of the window and its offset: `filters::detect`).
    pub(super) fn resume_slid(&mut self, kept: &[u8], window: usize, base: u64) {
        match self {
            Encoder::Rar5(encoder, Some(plan)) => width::on_pool(move || {
                encoder.resume_slid(kept);
                for (index, chunk) in kept.chunks(window).enumerate() {
                    let at = index * window;
                    filters::detect(chunk, base + at as u64, plan);
                    encoder.filter_kept(at, plan, base + at as u64);
                }
            }),
            Encoder::Rar5(encoder, None) => encoder.resume_slid(kept),
            Encoder::Rar29(encoder) => encoder.resume_slid(kept),
        }
    }

    /// Whether other encoders flush on this one's pool while it does.
    /// `Engine::share_pool`.
    #[cfg(feature = "parallel")]
    pub(super) fn share_pool(&mut self, engines: usize) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.share_pool(engines),
            Encoder::Rar29(encoder) => encoder.share_pool(engines),
        }
    }

    /// How many of a streamed member's next `left` bytes, in windows of
    /// `window`, come before this encoder's history slides, from a history
    /// of `history` bytes. `Engine::streamed_period`.
    #[cfg(feature = "parallel")]
    pub(super) fn streamed_period(&self, window: usize, history: usize, left: u64) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.streamed_period(window, history, left),
            Encoder::Rar29(encoder) => encoder.streamed_period(window, history, left),
        }
    }

    /// How many bytes a slide keeps of a history of `history` bytes.
    #[cfg(feature = "parallel")]
    pub(super) fn kept_by_slide(&self, history: usize) -> usize {
        match self {
            Encoder::Rar5(encoder, _) => encoder.kept_by_slide(history),
            Encoder::Rar29(encoder) => encoder.kept_by_slide(history),
        }
    }

    /// End the carried run and start one whole member of `size` bytes fed
    /// a window at a time, by the plan its class gives it: `head` is its
    /// first bytes as they are, before any filter
    /// (`encode::drive::Engine::start_member`).
    pub(super) fn start_member(&mut self, head: &[u8], size: u64) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.start_member(head, size),
            Encoder::Rar29(encoder) => encoder.start_member(head, size),
        }
    }

    /// Whether [`Encoder::start_member`] reads the head of a member of
    /// `size` bytes.
    pub(super) fn reads_head(&self, size: u64) -> bool {
        match self {
            Encoder::Rar5(encoder, _) => encoder.reads_head(size),
            Encoder::Rar29(encoder) => encoder.reads_head(size),
        }
    }

    /// The carried history's own bytes.
    pub(super) fn held_bytes(&self) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.held_bytes(),
            Encoder::Rar29(encoder) => encoder.held_bytes(),
        }
    }

    /// The match finder's structures and hints, which
    /// [`Encoder::held_bytes`] leaves out.
    pub(super) fn structure_bytes(&self) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.structure_bytes(),
            Encoder::Rar29(encoder) => encoder.structure_bytes(),
        }
    }

    /// What one fresh member of at most one parse block leaves this
    /// encoder's finder holding, through [`Encoder::whole_run`] when
    /// `whole_run` and through [`Encoder::region`] otherwise.
    pub(super) fn one_block_structure_bytes(&self, whole_run: bool) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.one_block_structure_bytes(whole_run),
            Encoder::Rar29(encoder) => encoder.one_block_structure_bytes(whole_run),
        }
    }

    /// The most this encoder holds while it encodes one member of `len`
    /// bytes, from its slice (`window` `None`) or a window at a time.
    pub(super) fn member_held_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.member_held_bytes(len, window),
            Encoder::Rar29(encoder) => encoder.member_held_bytes(len, window),
        }
    }

    /// [`Encoder::member_held_bytes`] with one finder charged, the larger,
    /// where the member's class decides between two.
    /// `Engine::member_one_finder_bytes`.
    pub(super) fn member_one_finder_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.member_one_finder_bytes(len, window),
            Encoder::Rar29(encoder) => encoder.member_one_finder_bytes(len, window),
        }
    }

    /// [`Encoder::member_one_finder_bytes`] for a caller's named ceiling,
    /// and given the member's `head`, its own class's finder.
    /// `Engine::member_named_finder_bytes`.
    pub(super) fn member_named_finder_bytes(
        &self,
        len: usize,
        window: Option<usize>,
        head: Option<&[u8]>,
    ) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.member_named_finder_bytes(len, window, head),
            Encoder::Rar29(encoder) => encoder.member_named_finder_bytes(len, window, head),
        }
    }

    /// [`Encoder::member_held_bytes`] where the chains walk the member.
    /// `Engine::member_chain_bytes`.
    pub(super) fn member_chain_bytes(&self, len: usize, window: Option<usize>) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.member_chain_bytes(len, window),
            Encoder::Rar29(encoder) => encoder.member_chain_bytes(len, window),
        }
    }

    /// Spec G 3.5's finder term over `span` positions.
    pub(super) fn finder_term(&self, span: usize) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.finder_term(span),
            Encoder::Rar29(encoder) => encoder.finder_term(span),
        }
    }

    /// What one fresh member of `len` bytes leaves this encoder's finder
    /// holding, through [`Encoder::whole_run`] when `whole_run` and
    /// through [`Encoder::region`] otherwise.
    pub(super) fn member_structure_bytes(&self, len: usize, whole_run: bool) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.member_structure_bytes(len, whole_run),
            Encoder::Rar29(encoder) => encoder.member_structure_bytes(len, whole_run),
        }
    }

    /// Whether a lone member is walked by another finder than the level's.
    /// `Engine::lone_finder_differs`.
    pub(super) fn lone_finder_differs(&self) -> bool {
        match self {
            Encoder::Rar5(encoder, _) => encoder.lone_finder_differs(),
            Encoder::Rar29(encoder) => encoder.lone_finder_differs(),
        }
    }

    /// Whether the finder is the tree (levels 4 and 5).
    pub(super) fn walks_tree(&self) -> bool {
        match self {
            Encoder::Rar5(encoder, _) => encoder.walks_tree(),
            Encoder::Rar29(encoder) => encoder.walks_tree(),
        }
    }

    /// The effort the member in progress is encoded by.
    /// `Engine::member_effort`.
    #[cfg(feature = "parallel")]
    pub(super) fn member_effort(&self) -> crate::encode::drive::Plan {
        match self {
            Encoder::Rar5(encoder, _) => encoder.member_effort(),
            Encoder::Rar29(encoder) => encoder.member_effort(),
        }
    }

    /// Encode what follows by `effort`. `Engine::walk_member_by`.
    pub(super) fn walk_member_by(&mut self, effort: crate::encode::drive::Plan) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.walk_member_by(effort),
            Encoder::Rar29(encoder) => encoder.walk_member_by(effort),
        }
    }

    /// Whether the member in progress is parsed lazily over the chains.
    /// `Engine::member_walks_lazy_chains`.
    #[cfg(feature = "parallel")]
    pub(super) fn member_walks_lazy_chains(&self) -> bool {
        match self {
            Encoder::Rar5(encoder, _) => encoder.member_walks_lazy_chains(),
            Encoder::Rar29(encoder) => encoder.member_walks_lazy_chains(),
        }
    }

    /// Hold every flush to `bytes` in flight. `Engine::hold_wave`.
    pub(super) fn hold_wave(&mut self, bytes: usize) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.hold_wave(bytes),
            Encoder::Rar29(encoder) => encoder.hold_wave(bytes),
        }
    }

    /// Never build the chains' pass across the pool.
    /// `Engine::no_chain_build`.
    pub(super) fn no_chain_build(&mut self) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.no_chain_build(),
            Encoder::Rar29(encoder) => encoder.no_chain_build(),
        }
    }

    /// Parse at most `parses` blocks at once. `Engine::hold_parses`.
    pub(super) fn hold_parses(&mut self, parses: usize) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.hold_parses(parses),
            Encoder::Rar29(encoder) => encoder.hold_parses(parses),
        }
    }

    /// Hold the chains' wave to `blocks` blocks. `Engine::hold_chain_width`.
    pub(super) fn hold_chain_width(&mut self, blocks: usize) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.hold_chain_width(blocks),
            Encoder::Rar29(encoder) => encoder.hold_chain_width(blocks),
        }
    }

    /// The most bytes one flush of this run will stage.
    /// `Engine::plan_flush`.
    pub(super) fn plan_flush(&mut self, bytes: usize) {
        match self {
            Encoder::Rar5(encoder, _) => encoder.plan_flush(bytes),
            Encoder::Rar29(encoder) => encoder.plan_flush(bytes),
        }
    }

    /// What this encoder's parses hold now: its scratches, its kept block
    /// outputs and its walkers' bins. `Engine::flight_bytes`.
    pub(super) fn flight_bytes(&self) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.flight_bytes(),
            Encoder::Rar29(encoder) => encoder.flight_bytes(),
        }
    }

    /// The most this encoder's parses hold for a flush of `bytes`.
    /// `Engine::flight_term`.
    pub(super) fn flight_term(&self, bytes: usize) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.flight_term(bytes),
            Encoder::Rar29(encoder) => encoder.flight_term(bytes),
        }
    }

    /// The most this encoder's parses hold for a flush of `bytes` ending a
    /// run of `span` bytes. `Engine::flight_term_over`.
    pub(super) fn flight_term_over(&self, bytes: usize, span: usize) -> u64 {
        match self {
            Encoder::Rar5(encoder, _) => encoder.flight_term_over(bytes, span),
            Encoder::Rar29(encoder) => encoder.flight_term_over(bytes, span),
        }
    }

    /// A whole member in one chunk, from a fresh history: the windowed
    /// encode of a member of one window, judged and filtered as
    /// [`Encoder::chunk`] judges its first window (base 0).
    pub(super) fn whole_run(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        width::on_pool(move || match self {
            Encoder::Rar5(encoder, Some(plan)) => {
                filters::detect(chunk, 0, plan);
                encoder.encode_whole_run(chunk, out, plan);
            }
            Encoder::Rar5(encoder, None) => encoder.encode_whole_run(chunk, out, &[]),
            Encoder::Rar29(encoder) => encoder.encode_whole_run(chunk, out),
        })
    }
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// The run's ONE encoder, built on the first compressed member that
    /// reaches it and kept: a solid set's state is this object's, and
    /// nothing allocates per member once it exists.
    pub(super) fn ensure_encoder(&mut self) {
        if self.encoder.is_none() {
            let mut encoder = self.new_encoder();
            encoder.plan_flush(self.lead_flush_bytes());
            self.encoder = Some(encoder);
        }
    }

    /// How many windows of one member a flush of the run's own encoder
    /// stages (`stage_window`): one under a caller's ceiling, whose sums
    /// count a window a flush; otherwise as many as the engine's batch
    /// takes, held to [`Run::lead_depth`] where the policy's
    /// `working_limit` needs it (`Run::choose_lead_depth`). How many
    /// windows a flush stages moves no byte (`stage_window` says why).
    pub(super) fn staged_depth(&self) -> usize {
        if self.dial_ceiling().is_some() {
            1
        } else {
            window_depth().min(self.lead_depth).max(1)
        }
    }

    /// The most bytes one flush of a member encoded a window at a time
    /// stages: one window, or where windows are staged
    /// ([`Run::staged_depth`]) as many as the engine's batch holds, which
    /// `Engine::may_stage` ends at `encode::drive::batch_blocks` parse
    /// blocks (`encode::drive::BATCH_BLOCKS_MOST` by default, read here
    /// rather than restated). A function of the options, the member table
    /// and the depth chosen.
    pub(super) fn lead_window_flush(&self) -> usize {
        let window = self.window_bytes();
        let depth = self.staged_depth();
        if depth <= 1 {
            return window;
        }
        let batch = crate::encode::drive::batch_blocks() * crate::encode::drive::PARSE_BLOCK_BYTES;
        window.max(batch.min(window.saturating_mul(depth)))
    }

    /// Chooses [`Run::lead_depth`] where no caller named a ceiling: the
    /// most windows a flush stages at which what the lead holds alone
    /// (`Run::alone_bytes`) fits the policy's `working_limit`, halved from
    /// the engine's batch down to one window. Each window fewer is a
    /// narrower wave of the lead's own member, which is wall; so the
    /// widest that fits. Where even one window does not fit, one window,
    /// since what passes then does not follow the parses (a held member's
    /// packed bytes, the finder), and narrowing would buy nothing. A
    /// function of the options and the member table.
    ///
    /// **Why the lead is admitted, not only the team.** A staged flush
    /// parses up to [`crate::encode::drive::BATCH_BLOCKS_MOST`] blocks at
    /// once, each with a scratch of a block's tokens, on as many threads
    /// as the pool has: counted 30 Sep 2026 on bin4g at `-m3`, 76 MB of
    /// the lead's parses at 32 threads where one window's were charged at
    /// 19.
    pub(super) fn choose_lead_depth(&mut self) {
        self.lead_depth = usize::MAX;
        // A storing level has no lead to admit, and its run allocates no
        // encoder, not even a probe (`tests/write_allocation.rs`).
        if self.options.stored() || self.dial_ceiling().is_some() || window_depth() <= 1 {
            return;
        }
        let limit = team_ceiling(self.options.memory.working_limit);
        let window = self.window_bytes().max(1);
        let batch = crate::encode::drive::batch_blocks() * crate::encode::drive::PARSE_BLOCK_BYTES;
        let mut depth = batch.div_ceil(window).max(1);
        loop {
            self.lead_depth = depth;
            if depth <= 1 || self.alone_bytes(self.hold, self.parses) <= limit {
                return;
            }
            depth /= 2;
        }
    }

    /// The most bytes one flush of the run's own encoder stages, for
    /// `Engine::plan_flush`: a solid run's members together (its batches
    /// span them, and the engine holds a batch to its own cap), or else
    /// the largest member, a window of it where it is encoded a window at
    /// a time. A function of the options and the member table.
    pub(super) fn lead_flush_bytes(&self) -> usize {
        // A member encoded a window at a time stages its windows where the
        // caller set no ceiling (`stage_window`), so one flush of it is a
        // batch of them, never more than the engine's batch cap.
        let window = self.lead_window_flush();
        let sizes = (0..self.members.len()).filter_map(|index| {
            let member = &self.members[index];
            if member.is_directory || member.size == 0 {
                return None;
            }
            let len = usize::try_from(member.size).unwrap_or(usize::MAX);
            let windowed = self.options.solid
                || matches!(member.payload, Payload::Reader { .. })
                || self.streams_packed(index);
            Some(if windowed && !self.options.solid {
                len.min(window)
            } else {
                len
            })
        });
        if self.options.solid {
            sizes.fold(0usize, usize::saturating_add)
        } else {
            sizes.max().unwrap_or(0)
        }
    }

    /// An encoder for this run's options: the run's own, and each crew's
    /// of the worker team (`Run::walk_team`). Every one of them is built
    /// here from the same figures, which is half of why a crew's packed
    /// bytes are the run's own encoder's; the other half is that an
    /// encoder's output for a member never depends on the members it
    /// encoded before (`encode::drive`'s module documentation).
    pub(super) fn new_encoder(&self) -> Encoder {
        self.encoder_held(self.hold)
    }

    /// [`Run::new_encoder`] held to `hold` bytes in flight
    /// (`Engine::hold_wave`), or not held at all.
    pub(super) fn encoder_held(&self, hold: Option<usize>) -> Encoder {
        self.encoder_capped(hold, self.parses)
    }

    /// Whether this run's encoders may build the chains' pass across the
    /// pool (`encode::chain::Build`): only a run that never fields a
    /// worker team, which is a solid run or one of fewer than two members
    /// with bytes. Beside a team the crews already have the width, and
    /// the build's tables, charged to the lead, would narrow the team
    /// under the default ceiling: counted 30 Sep 2026 on tree5k at -m1 and
    /// -m2 on a Zen 4 box of 24 and 32 cores, 0.85x to 0.88x of the pass.
    /// A function of the options and the member table, so it is the same
    /// on every run of the same inputs, and it moves no byte.
    pub(super) fn lead_builds(&self) -> bool {
        self.options.solid
            || self
                .members
                .iter()
                .filter(|member| !member.is_directory && member.size > 0)
                .nth(1)
                .is_none()
    }
}
