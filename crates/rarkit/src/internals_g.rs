//! Spec G entry points for this repository's tests and benches, behind
//! the `bench-internals` feature. Not part of the API; no shipped build
//! enables it.
//!
//! There is one entry, and it exists because a claim this package makes
//! is otherwise untestable from outside. The solid parse is PIPELINED
//! across the members of a run: a batch of members is staged and parsed
//! as one wave, so the blocks of one member are still being parsed while
//! the finder walks the member after it. The claim is that the batch is
//! a wave's WIDTH and never a member's bytes - that the same set written
//! at any depth is the same archive, to the byte, in a volume set as in
//! one archive. Without a way to set the depth from a test, the only
//! evidence for that would be the argument for it.

/// Runs `work` with this thread's pipelining depth set to `depth`
/// members, and puts the depth back afterwards.
///
/// A depth of 1 is a member at a time, which is the walk this engine had
/// before a batch existed, and it is the arm every identity test in
/// `tests/solid_volume_pipeline.rs` compares against.
pub fn with_batch_depth<T>(depth: usize, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_batch_depth(depth, work)
}

/// Runs `work` with this thread's STREAMING THRESHOLD set to `bytes`: the
/// working limit a member's held-whole write (spec G 3.5's sum, its packed
/// bytes counted twice) must fit for the member to be held where the
/// caller named no ceiling (the policy's own
/// `working_limit` in a shipped build), so that a test can make a member
/// of a few MiB take the walk a member of hundreds of MiB takes.
/// `u64::MAX` holds every member, which is the rule's test forced off.
pub fn with_stream_above<T>(bytes: u64, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_stream_above(bytes, work)
}

/// Runs `work` with the SEGMENT TEAM held to `width` engines on this
/// thread: how many engines a member longer than one stretch of its
/// streamed encode runs on (`write::engine`'s `Segments`), where the
/// writer otherwise chooses from the pool and the memory left. One is the
/// walk without a team, the arm `tests/segment_team.rs` compares every
/// other width against.
pub fn with_segment_width<T>(width: usize, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_segment_width(width, work)
}

/// Runs `work` with the segment team's hand-off ROLLING (`write::engine`'s
/// `Roll`: an engine takes each stretch as it is read, while the writing
/// thread reads the next) or a round at a time, on this thread, whatever
/// the shipped form is. A hand-off and never a byte, which is what
/// `tests/segment_roll.rs` compares.
#[cfg(feature = "parallel")]
pub fn with_segment_roll<T>(rolls: bool, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_segment_roll(rolls, work)
}

/// How many members this thread's writes have handed over rolling.
#[cfg(feature = "parallel")]
pub fn segment_rolled() -> usize {
    crate::write::engine::segment_rolled()
}

/// Runs `work` with a member's windows read AHEAD of its one engine
/// (`write::engine`'s `WindowsAhead`: the writing thread reads the next
/// windows while a flush parses the staged ones) or not, on this thread,
/// whatever the shipped form is. Never a byte, which is what
/// `tests/window_ahead.rs` compares.
pub fn with_window_ahead<T>(ahead: bool, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_window_ahead(ahead, work)
}

/// How many members this thread's writes have read ahead of their one
/// engine.
pub fn window_ahead_members() -> usize {
    crate::write::engine::window_ahead_members()
}

/// Runs `work` with the rules by cores reading `cores` physical cores:
/// how many engines the segment team runs and whether the large-member
/// lane reaches past one window follow the pool's width held to the
/// machine's physical cores, and a test names the figure rather than
/// depend on the box and the pool it runs on.
pub fn with_team_cores<T>(cores: usize, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_team_cores(cores, work)
}

/// Runs `work` with the LARGE-MEMBER LANE's reach set to `bytes` on this
/// thread: how large a reader member a crew of the worker team takes
/// whole (`Run::choose_large_lane`), where the writer otherwise reaches as
/// far past one window as costs the team no crew. Zero is the lane inside
/// one window, the arm `tests/lane_reach.rs` compares every reach against.
pub fn with_lane_reach<T>(bytes: u64, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_lane_reach(bytes, work)
}

/// How many rounds the segment team has run on this thread, and the most
/// engines one of them ran, since [`reset_segment_rounds`].
pub fn segment_rounds() -> (usize, usize) {
    crate::write::engine::segment_rounds()
}

/// Starts [`segment_rounds`] again from zero.
pub fn reset_segment_rounds() {
    crate::write::engine::reset_segment_rounds();
}

/// Runs `work` with this thread's WINDOW depth set to `depth`: the most
/// windows of one member (spec G 3.7.3) that one flush parses at once. A
/// depth of 1 is a window at a time, the walk this engine had before
/// windows were staged, and it is the arm `tests/one_member_windows.rs`
/// compares every other depth against.
pub fn with_window_depth<T>(depth: usize, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_window_depth(depth, work)
}

/// Runs `work` with every encoder in the process staging `blocks` parse
/// blocks a batch (`None`: the shipped sixty-four), its chain levels'
/// waves sliding or ending on their slowest block, and a member's windows
/// in a batch sharing one output buffer or each having their own (`None`:
/// the shipped setting of each), and puts all three back afterwards.
/// Process-wide, because the waves run on pool threads; calls are
/// serialised. `Some(32)`, `Some(false)` and `Some(false)` together are
/// the writer before 30 Sep 2026, the arm `tests/wave_batch_bytes.rs`
/// compares the shipped one against.
pub fn with_wave_arms<T>(
    blocks: Option<usize>,
    slide: Option<bool>,
    merge: Option<bool>,
    work: impl FnOnce() -> T,
) -> T {
    crate::encode::drive::wave_arms(blocks, slide, merge, work)
}

/// How many flushes have taken the chain levels' SLIDING waves in this
/// process so far, so a test can say the path it compares was taken.
pub fn slid_flushes() -> usize {
    crate::encode::drive::slid_flushes()
}

/// The most windows of one member a single flush has parsed on this
/// thread since [`forget_widest_flush`]; zero where no member was encoded
/// a window at a time.
pub fn widest_flush() -> usize {
    crate::write::engine::widest_flush()
}

/// Starts [`widest_flush`] again from zero.
pub fn forget_widest_flush() {
    crate::write::engine::forget_widest_flush();
}

/// Runs `work` with the slack multiple of a streamed member of a
/// non-solid run with no memory ceiling set to `multiple` on this thread
/// (`encode::drive::STREAMED_SLACK_MULTIPLE` is what a shipped build
/// uses). Setting it to the shipped `HISTORY_SLACK_MULTIPLE` gives such a
/// run the slides a run under a ceiling has, which is how a test compares
/// the two byte for byte.
pub fn with_streamed_slack<T>(multiple: usize, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_streamed_slack(multiple, work)
}

/// The slack multiple, in dictionaries, that the last member encoded a
/// window at a time on this thread ran its history at; zero before any.
pub fn last_streamed_slack() -> usize {
    crate::write::engine::last_streamed_slack()
}

/// The slack a shipped build gives every carried history but one, in
/// dictionaries, and the one it gives a streamed member of a non-solid
/// run with no memory ceiling.
pub const SLACK_MULTIPLES: (usize, usize) = (
    crate::encode::drive::HISTORY_SLACK_MULTIPLE,
    crate::encode::drive::STREAMED_SLACK_MULTIPLE,
);

/// The smallest dictionary, in bytes, at which such a member takes the
/// wider of [`SLACK_MULTIPLES`].
pub const STREAMED_SLACK_LEAST_DICTIONARY: usize =
    crate::encode::drive::STREAMED_SLACK_LEAST_DICTIONARY;

/// How many members the STREAMED walk has written on this thread since
/// [`reset_streamed_members`].
///
/// The walk this counts is the one that consumes a compressed member's
/// packed bytes as the encoder produces them, instead of holding them
/// whole (spec G 3.5 and 3.7.3). Whether a member takes it follows the
/// options, the output and the member's size together, so a test that
/// means to measure it has no other way to say that it did.
pub fn streamed_members() -> usize {
    crate::write::engine::streamed_members()
}

/// Starts the count in [`streamed_members`] again from zero.
pub fn reset_streamed_members() {
    crate::write::engine::reset_streamed_members();
}

/// Runs `work` with `chains` stored encrypted members' cipher chains
/// allowed AHEAD of the member being written, their held ciphertext
/// capped at `cap` bytes, on this thread.
/// Zero chains is the walk without them.
pub fn with_chains_ahead<T>(chains: usize, cap: Option<u64>, work: impl FnOnce() -> T) -> T {
    crate::write::engine::with_chains_ahead(chains, cap, work)
}

/// How many members this thread has written from a chain that ran ahead,
/// since [`reset_chain_members`].
pub fn chain_members() -> usize {
    crate::write::engine::chain_members()
}

/// What the last five second wait of a writing thread on the chain it was
/// taking from looked like (what the writer had of what it waited for,
/// what the chain held and was allowed), taken; `None` where no write
/// waited that long.
pub fn chain_stall() -> Option<String> {
    crate::write::engine::chain_stall()
}

/// Starts the count in [`chain_members`] again from zero.
pub fn reset_chain_members() {
    crate::write::engine::reset_chain_members();
}

/// The hold the last write built on this thread chose for its encoders:
/// `Some(None)` unheld (the widest), `Some(Some(bytes))` held to that many
/// bytes, `None` where this thread has built no write.
///
/// Under a caller's memory ceiling the writer holds its lead encoder to a
/// window or a parse block where the unheld one would not fit (spec G
/// 3.5). The choice is taken when the write is built, before a byte of
/// any member is read, from the options and the member table alone; what
/// a write then HOLDS (`WriteReport::peak_working_memory`) follows its
/// threads' timing as well. A test of the choice reads it here.
pub fn last_chosen_hold() -> Option<Option<usize>> {
    crate::write::engine::last_chosen_hold()
}

/// Which admission the last write on this thread took under a SMALL LIMIT
/// NOBODY NAMED (a `working_limit` whose budget is under 512 MiB with
/// `limit_named` false, which is what an environment's memory cap leaves
/// the default policy): `Some(false)` the default's own admission,
/// `Some(true)` the small named path's byte-neutral dials, `None` where
/// no such write has run since [`forget_rung`]. The choice is a function
/// of the options and the member table (spec G 3.7.3).
pub fn last_rung() -> Option<bool> {
    crate::write::engine::last_rung()
}

/// Forget what [`last_rung`] reads.
pub fn forget_rung() {
    crate::write::engine::forget_rung();
}

/// How many members this thread has written from a WORKER TEAM batch
/// since [`reset_team_prepared`]: members of a non-solid compressed run
/// encoded ahead, several at once, and written in `add` order. A test
/// that compares the team's archive with the member-at-a-time walk's has
/// no other way to say that the team encoded what it compared.
pub fn team_prepared() -> usize {
    crate::write::engine::team_prepared()
}

/// How many non-empty WORKER TEAM batches this thread has planned since
/// [`reset_team_prepared`], so a test can say a batch spans directory
/// members rather than ending at each one.
pub fn team_batches() -> usize {
    crate::write::engine::team_batches()
}

/// How many packed buffers the worker team's pool allocated FRESH on this
/// thread since [`reset_team_prepared`], rather than reusing one it kept
/// (`Run::lend_packed`): a test's check that no buffer is allocated,
/// regrown and freed per member.
pub fn packed_fresh() -> usize {
    crate::write::engine::packed_fresh()
}

/// Sets, or with `None` clears, the calling thread's floor for the store
/// rule's whole-member vote (spec G 3.8.3: a source that can seek is
/// voted on across its whole length from 4 GiB), so that a test can reach
/// that vote with a member it can hold. The vote is taken on the thread
/// that calls a `finish_` method.
pub fn set_whole_vote_from(from: Option<u64>) {
    crate::write::engine::set_whole_vote_from(from);
}

/// Starts the counts in [`team_prepared`], [`team_batches`] and
/// [`packed_fresh`] again from zero.
pub fn reset_team_prepared() {
    crate::write::engine::reset_team_prepared();
}

/// How many READER members this thread's solid batches have staged since
/// [`reset_readers_batched`], and how many of those were staged a second
/// time, from the bytes the writer kept, after a volume boundary
/// discarded the batch they were first staged in. A test that compares a
/// volume set of readers with the member-at-a-time walk has no other way
/// to say that the set was batched, or that a discard was met.
pub fn readers_batched() -> (usize, usize) {
    crate::write::engine::readers_batched()
}

/// Starts the counts in [`readers_batched`] again from zero.
pub fn reset_readers_batched() {
    crate::write::engine::reset_readers_batched();
}

/// Spec G 3.8.2's plan for `bytes` as a member's first bytes: each span
/// `FilterPolicy::Detect` keeps, as (start, length, the transform's name).
/// For the filter count's diagnostics (the filter count script).
pub fn filter_plan(bytes: &[u8]) -> Vec<(usize, usize, String)> {
    let mut plan = Vec::new();
    crate::write::filters::detect(bytes, 0, &mut plan);
    plan.into_iter()
        .map(|span| (span.start, span.len, format!("{:?}", span.kind)))
        .collect()
}

/// Every candidate's probe total over one region, in bits, the
/// unfiltered probe first as "None"; an address transform that changed
/// no byte is left out, as detection leaves it out.
pub fn filter_probe_totals(region: &[u8], offset: u64) -> Vec<(String, u64)> {
    crate::write::filters::probe_totals(region, offset)
}

/// How many crews this thread's last WORKER TEAM walk ran with, or zero
/// where none has: the width the options, the pool and the memory policy
/// gave it (`Run::team_width`), which no byte of the archive shows.
pub fn team_crews() -> usize {
    crate::write::engine::team_crews()
}

/// The largest member, in bytes, this thread's last WORKER TEAM walk
/// took (`Run::choose_team_most`), or zero where none has run.
pub fn team_member_most() -> u64 {
    crate::write::engine::team_member_most()
}

/// The LARGE-MEMBER LANE of this thread's last worker team walk
/// (`Run::choose_large_lane`): how many crews it had and the largest
/// member it took, or zeros where it had none.
pub fn team_large() -> (usize, u64) {
    crate::write::engine::team_large()
}

/// Where spec G 3.8.3's sixteen samples of a span of `len` bytes start,
/// and how long each is, for the store sampler's count
/// (`examples/g_store_sample_probe.rs`).
pub fn store_sample_starts(len: usize) -> (Vec<usize>, usize) {
    (
        crate::write::store::sample_starts(len).collect(),
        crate::write::store::SAMPLE_BYTES.min(len),
    )
}

/// How many of a member's samples may compress and the member still be
/// stored, by its declared size (the shipped default).
pub fn store_most_misses(size: u64) -> usize {
    crate::write::store::most_misses(size, false)
}

/// The store rule's length of every sample of `samples`, summed: by one
/// judge kept between them, or (`fresh`) by one built for each; counted,
/// or (`packed`, `WriteOptions::store_packed_samples`) packed in full.
pub fn store_probe_whole(samples: &[&[u8]], fresh: bool, packed: bool) -> u64 {
    crate::write::store::probe_whole(samples, fresh, packed)
}

/// The stages of one store sample, as bits of a mask
/// (`encode::rar5::stages`): 1 build the chains, 2 link, 4 parse, 8 cut,
/// 16 count and code lengths, 32 codes and tables, 64 the whole emit, 128
/// forget.
pub struct StoreSampleStages(crate::encode::rar5::stages::Stages);

impl StoreSampleStages {
    /// A sampler's pieces for samples of `sample` bytes, over the store
    /// rule's dictionary.
    pub fn new(sample: usize) -> StoreSampleStages {
        StoreSampleStages(crate::encode::rar5::stages::Stages::new(
            crate::memory::MemoryPolicy::MIN_DICTIONARY as usize,
            sample,
        ))
    }

    /// Run the stages of `mask` over `sample`.
    pub fn run(&mut self, sample: &[u8], mask: u32) -> u64 {
        self.0.run(sample, mask)
    }
}
