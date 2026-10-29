//! Spec H3 entry points for this repository's tests, benches and fuzz
//! targets, behind the `bench-internals` feature. Not part of the API; no
//! shipped build enables it.
//!
//! Spec F's container walk does not exist yet, so a caller hands the
//! member's packed bytes and its declared sizes straight in. The driving
//! loop below is what spec F's extract path will do: begin a block when
//! none is in force, run until the member's room is used up, drain.

use crate::Result;

pub use crate::error::Rar20Fault;

/// The RAR 2.0 dictionary a member's header selects: `65,536 << n` for `n`
/// in 0 to 6, so 64 KiB to 1 MiB.
pub fn dictionary_size(bits: u8) -> u32 {
    65_536u32 << bits.min(4)
}

/// One RAR 2.0 stream: one member, or a whole solid chain fed member by
/// member.
///
/// The driver itself is `lz20::Rar20Chain`, because the container package
/// reads an archive COMMENT through it - a comment is a stream like a
/// member's - and a driver behind a test-only feature could not be
/// reached from there.
pub struct Stream(crate::lz20::Rar20Chain);

impl Stream {
    /// A stream with a `capacity` byte dictionary.
    pub fn new(capacity: u32) -> Stream {
        Stream(crate::lz20::Rar20Chain::new(capacity))
    }

    /// Decode one member of `unpacked` bytes from its own packed data.
    pub fn member(&mut self, packed: &[u8], unpacked: u64) -> Result<Vec<u8>> {
        self.0.decode_next(packed, unpacked)
    }
}

/// Decode one non solid member.
pub fn decode_member(packed: &[u8], capacity: u32, unpacked: u64) -> Result<Vec<u8>> {
    Stream::new(capacity).member(packed, unpacked)
}

/// What a RAR 5 writer stores for a span it filters, in place: `kind` is
/// the record's type field (0 delta, 1 x86 call, 2 x86 call and jump, 3
/// ARM), `channels` the delta channel count and `start` the span's member
/// relative start (SPEC-C parts 1, 2, 4 and 6). The transform the writer
/// runs, so a test can hold it to the specification's vectors.
pub fn rar5_filter_encode(kind: u8, channels: u8, start: u64, data: &mut [u8]) {
    use crate::encode::filter::{encode_in_place, FilterKind};
    let kind = match kind {
        0 => FilterKind::Delta(channels),
        1 => FilterKind::X86Call,
        2 => FilterKind::X86CallJump,
        _ => FilterKind::Arm,
    };
    encode_in_place(kind, data, start, &mut Vec::new());
}

/// Encode `input` as one RAR 5 member's packed data, at spec G's level
/// `level` with a `dictionary` byte window (spec H3 section 6).
pub fn rar5_encode(input: &[u8], level: u8, dictionary: u32) -> Vec<u8> {
    let options = crate::encode::rar5::EncodeOptions::for_level(level, dictionary);
    crate::encode::rar5::Rar5Encoder::new(options).encode(input)
}

/// Encode `input` as one RAR 5 member with the plan SPELLED OUT rather
/// than taken from the level: `<lazy|optimal>:<chain|tree>:<depth>:<enough>`.
///
/// The level ladder's sweeps, and nothing else: it is how a point that is
/// not on the shipped ladder is measured without rebuilding the crate for
/// every point. `None` where the spelling is not one. See
/// `encode::drive::Plan::spelled`.
pub fn rar5_encode_spelled(input: &[u8], plan: &str, dictionary: u32) -> Option<Vec<u8>> {
    let options = crate::encode::rar5::EncodeOptions::spelled(plan, dictionary)?;
    Some(crate::encode::rar5::Rar5Encoder::new(options).encode(input))
}

/// [`rar5_encode_spelled`] over each of `members` in turn with ONE
/// encoder, as a non-solid set's writer uses it: what a small-members
/// sweep of the plan dials measures, the encoder's structures paid for
/// once rather than once a member.
pub fn rar5_encode_each_spelled(
    members: &[&[u8]],
    plan: &str,
    dictionary: u32,
) -> Option<Vec<Vec<u8>>> {
    let options = crate::encode::rar5::EncodeOptions::spelled(plan, dictionary)?;
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    Some(members.iter().map(|input| encoder.encode(input)).collect())
}

/// [`rar5_encode_each_spelled`] for the RAR 2.9 encoder.
pub fn rar29_encode_each_spelled(
    members: &[&[u8]],
    plan: &str,
    dictionary: u32,
) -> Option<Vec<Vec<u8>>> {
    let options = crate::encode::rar29::EncodeOptions::spelled(plan, dictionary)?;
    let mut encoder = crate::encode::rar29::Rar29Encoder::new(options);
    Some(members.iter().map(|input| encoder.encode(input)).collect())
}

/// [`rar5_encode_spelled`] for the RAR 2.9 encoder.
pub fn rar29_encode_spelled(input: &[u8], plan: &str, dictionary: u32) -> Option<Vec<u8>> {
    let options = crate::encode::rar29::EncodeOptions::spelled(plan, dictionary)?;
    Some(crate::encode::rar29::Rar29Encoder::new(options).encode(input))
}

/// [`rar5_encode_spelled`] over a SOLID set, so the many small members
/// shape can be swept on the same dials as the single member one.
pub fn rar5_encode_solid_spelled(
    members: &[&[u8]],
    plan: &str,
    dictionary: u32,
) -> Option<Vec<Vec<u8>>> {
    let options = crate::encode::rar5::EncodeOptions::spelled(plan, dictionary)?;
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    Some(
        members
            .iter()
            .map(|input| {
                let mut out = Vec::new();
                encoder.encode_chunk(input, true, &mut out);
                out
            })
            .collect(),
    )
}

/// [`rar5_encode_solid_spelled`] for the RAR 2.9 encoder.
pub fn rar29_encode_solid_spelled(
    members: &[&[u8]],
    plan: &str,
    dictionary: u32,
) -> Option<Vec<Vec<u8>>> {
    let options = crate::encode::rar29::EncodeOptions::spelled(plan, dictionary)?;
    let mut encoder = crate::encode::rar29::Rar29Encoder::new(options);
    Some(
        members
            .iter()
            .map(|input| {
                let mut out = Vec::new();
                encoder.encode_chunk(input, true, &mut out);
                out
            })
            .collect(),
    )
}

/// Encode `input` as one RAR 2.9 member's packed data, at spec G's level
/// `level` with a `dictionary` byte window (spec H3 section 7).
pub fn rar29_encode(input: &[u8], level: u8, dictionary: u32) -> Vec<u8> {
    let options = crate::encode::rar29::EncodeOptions::for_level(level, dictionary);
    crate::encode::rar29::Rar29Encoder::new(options).encode(input)
}

/// Encode each of `members` in turn with ONE RAR 5 encoder, which is how
/// spec G's writer will use it: the encoder keeps its working memory
/// between members, and a member's bytes must not depend on the members
/// before it.
pub fn rar5_encode_each(members: &[&[u8]], level: u8, dictionary: u32) -> Vec<Vec<u8>> {
    let options = crate::encode::rar5::EncodeOptions::for_level(level, dictionary);
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    members.iter().map(|input| encoder.encode(input)).collect()
}

/// [`rar5_encode_each`] for the RAR 2.9 encoder.
pub fn rar29_encode_each(members: &[&[u8]], level: u8, dictionary: u32) -> Vec<Vec<u8>> {
    let options = crate::encode::rar29::EncodeOptions::for_level(level, dictionary);
    let mut encoder = crate::encode::rar29::Rar29Encoder::new(options);
    members.iter().map(|input| encoder.encode(input)).collect()
}

/// Encode `members` as one SOLID set with one encoder: each member
/// continues the one before it, so the output history and the match
/// finder's index over it carry across the member boundary (spec G 3.9,
/// spec H3 section 4). Every member still begins its own block chain.
pub fn rar5_encode_solid(members: &[&[u8]], level: u8, dictionary: u32) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar5::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    members
        .iter()
        .map(|input| {
            let mut out = Vec::new();
            encoder.encode_chunk(input, true, &mut out);
            out
        })
        .collect()
}

/// [`rar5_encode_solid`] for the RAR 2.9 encoder.
pub fn rar29_encode_solid(members: &[&[u8]], level: u8, dictionary: u32) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar29::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar29::Rar29Encoder::new(options);
    members
        .iter()
        .map(|input| {
            let mut out = Vec::new();
            encoder.encode_chunk(input, true, &mut out);
            out
        })
        .collect()
}

/// Encode `members` as one solid set through the BATCHED entry: the
/// chunks are STAGED together and parsed as one wave, so the parse stays
/// wide across the member boundaries instead of joining at every one of
/// them. `slack` shrinks the history buffer so that a batch meets a
/// slide, which is what cuts one.
///
/// The differential arm of [`rar5_encode_solid`]: a batch must not move a
/// byte, whatever it holds.
pub fn rar5_encode_solid_batched(
    members: &[&[u8]],
    slack: Option<usize>,
    level: u8,
    dictionary: u32,
) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar5::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    if let Some(slack) = slack {
        encoder.set_history_slack(slack);
    }
    let mut packed = Vec::new();
    let mut at = 0;
    while at < members.len() {
        let mut staged = 0;
        while at + staged < members.len() {
            let chunk = members[at + staged];
            if staged > 0 && !encoder.may_stage(chunk.len()) {
                break;
            }
            encoder.stage(chunk, true);
            staged += 1;
        }
        for member in encoder.flush().iter_mut() {
            packed.push(std::mem::take(member));
        }
        at += staged;
    }
    packed
}

/// [`rar5_encode_solid_batched`] for the RAR 2.9 encoder.
pub fn rar29_encode_solid_batched(
    members: &[&[u8]],
    slack: Option<usize>,
    level: u8,
    dictionary: u32,
) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar29::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar29::Rar29Encoder::new(options);
    if let Some(slack) = slack {
        encoder.set_history_slack(slack);
    }
    let mut packed = Vec::new();
    let mut at = 0;
    while at < members.len() {
        let mut staged = 0;
        while at + staged < members.len() {
            let chunk = members[at + staged];
            if staged > 0 && !encoder.may_stage(chunk.len()) {
                break;
            }
            encoder.stage(chunk, true);
            staged += 1;
        }
        for member in encoder.flush().iter_mut() {
            packed.push(std::mem::take(member));
        }
        at += staged;
    }
    packed
}

/// Encode `members` as a solid set the way the writer did BEFORE the
/// index carried: each member is handed its history IN ITS SPAN, so the
/// finder indexes that history again for every member. The second arm of
/// the differential that says carrying the index does not move a byte.
pub fn rar5_encode_solid_rebuilt(members: &[&[u8]], level: u8, dictionary: u32) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar5::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    let mut history: Vec<u8> = Vec::new();
    members
        .iter()
        .map(|input| {
            let mut span = history.clone();
            let emit_from = span.len();
            span.extend_from_slice(input);
            let mut out = Vec::new();
            encoder.encode_region(&span, emit_from, true, &mut out);
            let from = span.len().saturating_sub(dictionary as usize);
            history = span[from..].to_vec();
            out
        })
        .collect()
}

/// [`rar5_encode_solid_rebuilt`] for the RAR 2.9 encoder.
pub fn rar29_encode_solid_rebuilt(members: &[&[u8]], level: u8, dictionary: u32) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar29::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar29::Rar29Encoder::new(options);
    let mut history: Vec<u8> = Vec::new();
    members
        .iter()
        .map(|input| {
            let mut span = history.clone();
            let emit_from = span.len();
            span.extend_from_slice(input);
            let mut out = Vec::new();
            encoder.encode_region(&span, emit_from, true, &mut out);
            let from = span.len().saturating_sub(dictionary as usize);
            history = span[from..].to_vec();
            out
        })
        .collect()
}

/// [`rar5_encode_solid`] with the history SLID: the buffer is cut down
/// to `slack` bytes past the dictionary, so it fills and the engine
/// keeps the dictionary and builds its index again over what it kept. A
/// slide must not move a byte, because what it keeps is everything a
/// match may still reach.
pub fn rar5_encode_solid_slid(
    members: &[&[u8]],
    slack: usize,
    level: u8,
    dictionary: u32,
) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar5::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    encoder.set_history_slack(slack);
    members
        .iter()
        .map(|input| {
            let mut out = Vec::new();
            encoder.encode_chunk(input, true, &mut out);
            out
        })
        .collect()
}

/// [`rar5_encode_solid_slid`] for the RAR 2.9 encoder.
pub fn rar29_encode_solid_slid(
    members: &[&[u8]],
    slack: usize,
    level: u8,
    dictionary: u32,
) -> Vec<Vec<u8>> {
    let mut options = crate::encode::rar29::EncodeOptions::for_level(level, dictionary);
    // A member of a solid set is never LONE, as the writer has it
    // (`Run::encoder_held`): its bytes may not follow how it was batched.
    options.plan.lone = None;
    let mut encoder = crate::encode::rar29::Rar29Encoder::new(options);
    encoder.set_history_slack(slack);
    members
        .iter()
        .map(|input| {
            let mut out = Vec::new();
            encoder.encode_chunk(input, true, &mut out);
            out
        })
        .collect()
}

/// Encode one member fed in `window` byte chunks, which is spec G
/// 3.7.3's windowed encode: the member is never held whole and each
/// window continues the one before it.
pub fn rar5_encode_windowed(input: &[u8], window: usize, level: u8, dictionary: u32) -> Vec<u8> {
    let options = crate::encode::rar5::EncodeOptions::for_level(level, dictionary);
    let mut encoder = crate::encode::rar5::Rar5Encoder::new(options);
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let to = (at + window).min(input.len());
        let last = to == input.len();
        encoder.encode_chunk(&input[at..to], last, &mut out);
        at = to;
        if last {
            break;
        }
    }
    out
}

/// How much of a member one parse covers: the block the incompressible
/// sample is taken over, so `examples/ladder_probe` can walk a file the
/// way the encoder does.
pub const PARSE_BLOCK_BYTES: usize = crate::encode::drive::PARSE_BLOCK_BYTES;

/// Four byte repeats per thousand sampled positions of one parse block:
/// `encode::sample`'s reading, exposed so the threshold it ships can be
/// read off a histogram of real corpora rather than asserted.
pub fn sample_yield_per_mille(block: &[u8]) -> u32 {
    crate::encode::sample::yield_per_mille(block)
}

/// Whether that reading clears the shipped threshold.
pub fn sample_worth(yield_per_mille: u32) -> bool {
    crate::encode::sample::worth(yield_per_mille)
}

/// `encode::class`'s reading of `span`, far links a byte in thousandths
/// and the greedy parse's tokens a thousand positions, or none where the
/// span is under a megabyte: read through sixteen windows spread across
/// the span, so `examples/class_probe` can print the head's reading (the
/// span's first megabyte, which is what the writer reads) beside the whole
/// member's.
pub fn class_far_links_per_mille(span: &[u8]) -> Option<(u32, u32)> {
    crate::encode::class::of_span(span)
        .map(|reading| (reading.per_mille(), reading.tokens_per_mille()))
}

/// [`class_far_links_per_mille`] with the greedy parse run over every
/// `stride`th window from window `first` (every window still counted): a
/// cheaper reading, for the probe that prices it.
pub fn class_far_links_parsing(span: &[u8], stride: usize, first: usize) -> Option<(u32, u32)> {
    crate::encode::class::of_span_parsing(span, stride, first)
        .map(|reading| (reading.per_mille(), reading.tokens_per_mille()))
}

/// The reading by the DEALT form (`encode::class`, which the encoder uses
/// on a pool of two threads and more): the same figures as
/// [`class_far_links_per_mille`] over a head, on up to `workers` threads of
/// the caller's pool, or in turn where `workers` is one.
/// For `examples/class_probe --cost-wide`, which times and counts it.
pub fn class_far_links_wide(head: &[u8], workers: usize) -> Option<(u32, u32)> {
    crate::encode::class::of_head_dealt(head, workers)
        .map(|reading| (reading.per_mille(), reading.tokens_per_mille()))
}

/// `encode::class`'s second statistic over a head: how many matches of 16
/// bytes or more the reading's greedy parse takes, by the serial form and
/// by the dealt form on `workers` threads (the two agree; a probe prints
/// both).
pub fn class_long_matches(head: &[u8], workers: usize) -> Option<(u32, u32)> {
    let serial = crate::encode::class::of_span(head.get(..CLASS_HEAD_BYTES)?)?;
    let dealt = crate::encode::class::of_head_dealt(head, workers)?;
    Some((serial.long_matches(), dealt.long_matches()))
}

/// The head a member's class is read from: its first megabyte.
pub const CLASS_HEAD_BYTES: usize = crate::encode::class::HEAD_BYTES;

/// Run `work` on a pool of exactly `threads` threads, so a test can hold
/// API promise 6 to account: the same bytes at any thread count. Without
/// the `parallel` feature there is one thread and `work` simply runs.
pub fn on_threads<T: Send>(threads: usize, work: impl FnOnce() -> T + Send) -> T {
    #[cfg(feature = "parallel")]
    {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("a thread pool")
            .install(work)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = threads;
        work()
    }
}

/// The tree walk alone, timed piece by piece: see
/// `crate::encode::drive::WalkProbe`.
#[cfg(feature = "parallel")]
pub use crate::encode::drive::{walk_probe, WalkProbe};

// ------------------------------- the multimedia predictor's lane arms

/// The most any of spec D 1.2.2 step 5's accumulators may hold before its
/// channel adapts, from spec D 1.4.2.
///
/// It is the whole reason the shipped model may narrow its accumulator to
/// a `u16` on x86-64, so a campaign that drives the predictor asserts it
/// rather than taking the spec's word for it.
#[cfg(feature = "audio-lane-ref")]
pub const AUDIO_ACCUMULATOR_BOUND: u32 = crate::lz20::lane_ref::ACCUMULATOR_BOUND;

/// Whether THIS BUILD's multimedia predictor runs the narrow lane, which
/// is `i16` multipliers and `u16` accumulators. True on x86-64 alone.
#[cfg(feature = "audio-lane-ref")]
pub const AUDIO_NARROW_LANE: bool = crate::lz20::lane_ref::NARROW_LANE;

/// Run the SHIPPED multimedia predictor over `residuals`, rotating
/// `channels` channels, decoder direction: the narrow arm on x86-64 and
/// the wide arm on every other target.
#[cfg(feature = "audio-lane-ref")]
pub fn audio_shipped(channels: usize, residuals: &[u8]) -> Vec<u8> {
    crate::lz20::lane_ref::shipped(channels, residuals)
}

/// Run a WIDE reference of spec D 1.2.2 over the same residuals and the
/// same rotation, and answer its bytes with the largest accumulator any
/// channel held.
///
/// The reference is written in the spec's own shape rather than the
/// shipped model's, so the two disagree where either is wrong.
#[cfg(feature = "audio-lane-ref")]
pub fn audio_reference(channels: usize, residuals: &[u8]) -> (Vec<u8>, u32) {
    crate::lz20::lane_ref::reference(channels, residuals)
}

/// Multimedia SAMPLES THIS THREAD has put through the predictor since
/// the last [`reset_audio_samples`].
///
/// It answers what a target list cannot: whether a target that COULD
/// reach the predictor ever does.
#[cfg(feature = "audio-lane-ref")]
pub fn audio_samples() -> u64 {
    crate::lz20::lane_ref::samples()
}

/// Set [`audio_samples`] back to zero.
#[cfg(feature = "audio-lane-ref")]
pub fn reset_audio_samples() {
    crate::lz20::lane_ref::reset_samples();
}
