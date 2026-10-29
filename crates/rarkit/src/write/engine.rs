//! The run: what `finish_into` and `finish_volumes` do (spec G section
//! 3.1), for both families and both layouts.
//!
//! The walk is one loop over the members in `add` order. Each member is
//! cut into fragments only when a volume fills; each fragment is a
//! complete header and a run of payload bytes copied through ONE buffer
//! whose size does not depend on the member. The engine never holds a
//! member and never copies a byte twice.

use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::checksum::blake2sp::Blake2sp;
use crate::checksum::Crc32;
use crate::encode::class;
use crate::encode::filter::FilterSpan;
use crate::encode::{rar29, rar5 as rar5_encode};
use crate::error::{Corruption, Error, ErrorKind};
use crate::memory::MemoryPolicy;
use crate::read::Progress;
use crate::types::{HostOs, Timestamp};
use crate::write::consts::*;
use crate::write::crypt::{
    padded_len, rar5_archive_encryption_body, ArchiveKey, Draw, HeaderKey, MemberCrypt,
    CIPHER_BLOCK,
};
use crate::write::options::{
    dictionary_power, fitted_dictionary, rar4_host_byte, rar5_host_byte, refuse, Resolved,
    COPY_CHUNK,
};
use crate::write::out::{Out, VolumeSource};
use crate::write::store::{self, Prefix};
use crate::write::width;
use crate::write::{
    filters, rar4, rar5, ChecksumKind, Digest, FilterPolicy, ReadSeek, WriteFormat, WriteReport,
};
use crate::Result;

use rar5::{Compression, Fragment};

/// A member's payload as the run reads it: bytes in memory, or a stream
/// read exactly once.
///
/// The public `write::Payload` has a third kind, a source that can also
/// SEEK. The run asks such a source for the store rule's samples before it
/// plans anything (`Run::vote_whole_members`) and from then on reads it as
/// the reader it is in every other respect, so that kind has no variant
/// here and no path of the run knows it ([`Planned::seekable`] holds it
/// until then).
pub(crate) enum Stream<'a> {
    /// Already in memory, all of it.
    Bytes(&'a [u8]),
    /// Read exactly once, in order.
    Reader {
        /// The stream. How many bytes it will produce is the member's
        /// size (`Planned::size`).
        reader: &'a mut (dyn Read + Send),
        /// The CRC32 over them, when the caller has it.
        crc32: Option<u32>,
    },
}

// The name the run's paths were written under, when the public type was
// the one they read.
use Stream as Payload;

// The run's parts, one module a seam.
#[cfg(test)]
mod census;
#[cfg(all(test, feature = "parallel"))]
mod tests;
#[cfg(test)]
pub(crate) use census::*;
mod chains;
use chains::*;
#[cfg(feature = "bench-internals")]
pub(crate) use chains::{chain_members, chain_stall, reset_chain_members, with_chains_ahead};
mod digest;
use digest::*;
mod copy;
use copy::*;
mod headers;
use headers::*;
mod recovery;
#[cfg(test)]
pub(crate) use recovery::set_recovery_copy_limit;
mod encoder;
mod volume;
use encoder::*;
#[cfg(feature = "bench-internals")]
pub(crate) use encoder::{forget_widest_flush, widest_flush, with_window_depth};
mod sample;
#[cfg(feature = "bench-internals")]
pub(crate) use sample::set_whole_vote_from;
mod solid;
#[cfg(feature = "bench-internals")]
pub(crate) use solid::with_batch_depth;
use solid::*;
mod streamed;
use streamed::*;
#[cfg(feature = "bench-internals")]
pub(crate) use streamed::{
    last_streamed_slack, reset_streamed_members, streamed_members, with_stream_above,
    with_streamed_slack,
};
mod roll;
#[cfg(feature = "parallel")]
use roll::*;
#[cfg(feature = "bench-internals")]
pub(crate) use roll::{segment_rolled, with_segment_roll};
mod segment;
use segment::*;
#[cfg(feature = "bench-internals")]
pub(crate) use segment::{
    reset_segment_rounds, segment_rounds, window_ahead_members, with_segment_width,
    with_window_ahead,
};
#[cfg(all(test, feature = "parallel"))]
pub(crate) use segment::{segment_afforded_least, segment_team};
mod lane;
use lane::*;
#[cfg(feature = "bench-internals")]
pub(crate) use lane::{with_lane_reach, with_team_cores};
mod team;
use team::*;
#[cfg(feature = "bench-internals")]
pub(crate) use team::{
    packed_fresh, readers_batched, reset_readers_batched, reset_team_prepared, team_batches,
    team_crews, team_large, team_member_most, team_prepared,
};
mod accounting;
use accounting::*;
#[cfg(test)]
pub(crate) use accounting::{forget_packed_growth, packed_grew};
mod admission;
use admission::*;
#[cfg(feature = "bench-internals")]
pub(crate) use admission::{forget_rung, last_chosen_hold, last_rung};

/// The most one window of a reader's compressed member holds, whatever
/// the dictionary says: a window is a working buffer and not a promise,
/// and the dictionary is already the ceiling on what a match can reach.
const MAX_WINDOW_BYTES: usize = 8 << 20;

/// One member as `Writer::add` recorded it, plus what the writer worked
/// out about it.
pub(crate) struct Planned<'a> {
    /// The name as the caller gave it: UTF-8, `/` separated.
    ///
    /// **Borrowed, not copied.** The member table is what spec G 7.3
    /// allows; a copy of every name is not, and the writer already holds
    /// the payload for `'a`, so the name costs the same lifetime and no
    /// allocation. `check_name` refuses on the caller's own bytes and
    /// the RAR 4 backslash form is built into a run-owned buffer at the
    /// header, so nothing here is rewritten.
    pub(crate) name: &'a [u8],
    /// Where the bytes come from.
    pub(crate) payload: Payload<'a>,
    /// The modification time to record.
    pub(crate) mtime: Option<Timestamp>,
    /// The attribute word, uninterpreted.
    pub(crate) attributes: u32,
    /// The host the attribute word is shaped for.
    pub(crate) host_os: HostOs,
    /// Whether this entry is a directory.
    pub(crate) is_directory: bool,
    /// How many payload bytes the member has.
    pub(crate) size: u64,
    /// The member's source where the caller gave one that can SEEK
    /// (`write::Payload::Seekable`), with its CRC32 if stated: held here,
    /// `payload` empty beside it, until the run's first act turns it into
    /// the reader `payload` then holds (`Run::vote_whole_members`).
    pub(crate) seekable: Option<(&'a mut (dyn ReadSeek + Send), Option<u32>)>,
}

/// Runs the whole write.
pub(crate) fn run<V: VolumeSource, P: Progress>(
    options: Resolved,
    members: Vec<Planned<'_>>,
    source: V,
    progress: &mut P,
) -> Result<WriteReport> {
    // Every pool the write hands work to is no wider than `workers`
    // (`width`), from the key derivation on.
    let _width = width::enter(options.workers);
    let mut run = Run::new(options, members, source, progress)?;
    run.walk()?;
    Ok(run.report())
}

/// The state of one run.
struct Run<'a, 'p, V: VolumeSource, P: Progress> {
    options: Resolved,
    /// Where the run reports (spec G 3.13, SPEC-API 7.1).
    progress: &'p mut P,
    /// Payload bytes written so far over all members, which is what
    /// `Progress::output` is told.
    delivered: u64,
    members: Vec<Planned<'a>>,
    out: Out<V>,
    /// The dictionary the headers declare, fitted to the payload.
    dictionary: u64,
    /// Payload bytes still allowed in the volume now open.
    budget: u64,
    /// Bytes the volume now open spent on its signature and main header,
    /// which is where its first member can start. Only the FILE budget
    /// reads it, to tell "this volume is full" from "this member's header
    /// does not fit a whole volume".
    head_bytes: u64,
    /// The volume now open, zero based.
    volume: u32,
    /// The copy buffer, allocated once for the whole run.
    buffer: Vec<u8>,
    /// The member whose WHOLE payload `buffer` holds, read and hashed
    /// before its header was laid down (`Run::digest_before_header`), for
    /// the copy to write from there in place of a second read.
    buffered: Option<usize>,
    /// The read-ahead's buffers, allocated on the first member long
    /// enough to take it and kept for the rest of the run
    /// (`Run::copy_payload`, [`read_ahead`]).
    ahead_pool: Vec<Vec<u8>>,
    /// The header buffers, allocated once for the whole run.
    header_scratch: HeaderScratch,
    /// The locator's reserved width, and the offsets it will carry.
    reference: Option<ReferencePlan>,
    /// The DEFAULT layout's recovery locator: the width its offset is reserved at in every volume's main header,
    /// when this run writes one (`Run::default_locator_width`).
    default_locator: Option<usize>,
    /// Where the open volume's main header starts, for the correction
    /// that writes the recovery record's offset into its locator.
    main_at: u64,
    /// Cached headers for the quick-open block: the position each header
    /// sits at, and its image.
    cached: Vec<(u64, Vec<u8>)>,
    /// Whether a member is still open across the volume boundary.
    solid_run: bool,
    /// Whether the member NOW BEING WRITTEN was encoded as a continuation
    /// of the one before it, which is what its header says.
    ///
    /// It is the run's state taken once, before the member is encoded,
    /// and it is what every one of that member's FRAGMENTS carries. The
    /// run's own state cannot serve: a member split over a volume
    /// boundary has `Run::next_volume` clear the run between its first
    /// fragment and its second, so a header built from the live state
    /// said "solid" on one fragment of a member and "not solid" on the
    /// next. Spec G 3.10.2 lists everything that may differ between the
    /// fragments of one member and the compression information is not in
    /// it; the old engine refuses such a set outright ("RAR 5 split entry
    /// compression info changed").
    member_solid: bool,
    /// Where salts and initialisation vectors are drawn, in a fixed order.
    draw: Draw,
    /// What the archive derived once from the password.
    key: ArchiveKey,
    /// The cipher of the member being written, and what its header says.
    crypt: Option<MemberCrypt>,
    /// The initialisation vector the header now being written used, so a
    /// correction can reuse it.
    header_iv: [u8; 16],
    /// Chains ahead (`Run::choose_chains`): how many stored encrypted
    /// members' chains may run AHEAD of the member being written, 0 for
    /// today's walk; whether each reads on a thread of its own; the bytes
    /// of ciphertext they may hold between them; the first member whose
    /// vectors are not yet drawn; what was drawn ahead, in member order;
    /// the chains started, in member order; the gate of the chain the
    /// writing thread is taking from; the buffers they share; and the
    /// header vector drawn ahead for the member now being written.
    chains_most: usize,
    chains_split: bool,
    chains_budget: u64,
    chains_drawn: usize,
    chain_seals: std::collections::VecDeque<ChainSeal>,
    chains: std::collections::VecDeque<ChainEnd>,
    chain_live: Option<std::sync::Arc<ChainGate>>,
    chain_pool: Option<std::sync::Arc<ChainPool>>,
    /// The chain of the member being written, from its first fragment to
    /// its last, with the buffer a volume boundary cut.
    chain_now: Option<ChainTaking>,
    header_iv_next: Option<[u8; 16]>,
    /// The packed bytes of the member being written, empty for a stored
    /// one. This is the one buffer in the package whose size follows the
    /// member, and it is the HEADER's shape rather than the encoder's: a
    /// member header's packed size field IS this length, so it has to be
    /// known before the header is laid down. Section 3.7.3's windowed
    /// encode removes the whole-member INPUT buffer, which is what that
    /// section asks for; removing this one as well needs a packed size
    /// field written at a reserved width and corrected, which is not done yet.
    packed: Vec<u8>,
    /// The packed and unpacked bytes of the compressed members written so
    /// far, which is the only thing this run knows about how well its
    /// input compresses.
    ///
    /// A batch may not run past the volume now open (`Run::batch_solid`),
    /// and the room it has to stay inside is PACKED bytes while what the
    /// writer knows before it encodes is UNPACKED ones. Bounding the
    /// batch by the unpacked figure is safe and far too tight: on text at
    /// `-m3` it staged a quarter of the members a volume could hold, and
    /// the wave was that much narrower for it. So the batch estimates,
    /// from the ratio this run has actually seen, and an estimate that
    /// comes out wrong costs one discarded tail at the boundary and never
    /// a byte of anybody's output.
    packed_seen: u64,
    unpacked_seen: u64,
    /// The packed bytes of the members of a solid BATCH that have been
    /// encoded but not yet written, in member order from `ahead_from`.
    ///
    /// This is what pipelining the parse across a solid set's member
    /// boundaries costs, and it is the whole of what it costs: the batch
    /// is encoded as one wave, so the writer holds the packed output of
    /// the members it has not reached yet. `Engine::batch_cap` bounds the
    /// INPUT a batch stages and so bounds this.
    ahead: Vec<Vec<u8>>,
    /// The member `ahead[0]` belongs to.
    ahead_from: usize,
    /// How many of `ahead` hold a member's bytes.
    ahead_len: usize,
    /// The unpacked digest of each member of `ahead` that came from a
    /// READER, taken as the batch pulled it (`Run::batch_solid`); `None`
    /// for one whose bytes were in memory.
    ahead_digests: Vec<Option<Digest>>,
    /// In a VOLUME SET, the bytes each READER member of the batch was
    /// pulled to, end to end, kept until the batch after is staged: a
    /// batch whose tail lands past a volume boundary is discarded there
    /// and encoded again (`Run::may_batch`), and a reader is pulled once.
    /// At most one batch's input (`Engine::batch_cap`, or one window).
    /// Empty outside a volume set, where no batch is discarded.
    ahead_input: Vec<u8>,
    /// Where each reader member of the batch lies in `ahead_input`, in
    /// member order, with its unpacked digest.
    ahead_kept: Vec<(usize, Pulled)>,
    /// The reader members of a batch a volume boundary discarded before
    /// the writer reached them (`Run::next_volume`), in member order, with
    /// where each one's bytes lie in `restage_buf`: the batch after stages
    /// them from there and pulls nothing.
    restage: std::collections::VecDeque<(usize, Pulled)>,
    /// The bytes of `restage`, end to end.
    restage_buf: Vec<u8>,
    /// One past the last member the caller was told the writer has taken
    /// up (`Run::announce`).
    announced: usize,
    /// A reader whose pull for a batch FAILED, and the error it failed
    /// with: the member it belongs to returns it when the writer reaches
    /// it, which is where a member at a time would have met it, with
    /// every member before it written.
    pull_failed: Option<(usize, Error)>,
    /// Reader members of the NEXT batch, pulled by the writing thread
    /// while this batch's flush ran on the pool (`Run::batch_solid`), in
    /// `add` order: where each one's bytes lie in `prefetch_buf`, and its
    /// unpacked digest, or the error its pull ended in.
    prefetched: std::collections::VecDeque<(usize, Result<Pulled>)>,
    /// The bytes of `prefetched`, end to end, in ONE buffer kept between
    /// rounds, so what is held is what was pulled (a buffer a member kept
    /// its largest capacity, and held 50 MiB more on tree5k at -m5).
    prefetch_buf: Vec<u8>,
    /// The one encoder of the run, built when the first compressed
    /// member arrives and kept: a solid set's state is this object's, and
    /// nothing allocates per member once it exists.
    encoder: Option<Encoder>,
    /// One window of the member being compressed, which is what the
    /// encoder is handed. Its size follows the DICTIONARY and never the
    /// member. The HISTORY in front of it is the encoder's own, with the
    /// match finder's index live over it (spec H3 section 4); this
    /// package says only where a run starts and where it ends.
    scratch: Vec<u8>,
    /// The UNPACKED digest of a compressed member that arrived through a
    /// reader, taken as the windows passed, because there is no second
    /// chance to read those bytes.
    unpacked_digest: Option<Digest>,
    /// The ciphertext of one chunk. Allocated only when encrypting.
    cipher_out: Vec<u8>,
    /// The cipher every block but the first goes through, when the
    /// caller asked for encrypted headers (spec G 3.3.6).
    header_key: Option<HeaderKey>,
    /// The salt `header_key` was derived from, for the archive
    /// encryption header each volume opens with.
    header_salt: [u8; 16],
    /// The streamed encode in flight, when one is (see [`StreamState`]).
    stream: StreamState,
    /// The segment team (see [`Segments`]).
    segments: Segments,
    /// The largest simultaneous IN-USE total this run's buffers have
    /// reached, which is what `WriteReport::peak_working_memory`
    /// carries (decided 21 Sep 2026).
    ///
    /// It is carried ACROSS the run rather than read off at the end,
    /// and that is the whole of the rule. Several of the buffers in
    /// the sum are cleared before the run finishes - `stream.pending`
    /// twice in `write_member_streamed`, `scratch` on every window,
    /// `ahead`'s slots as each batched member is written - so a figure
    /// taken at report time reports a run that peaked at hundreds of
    /// megabytes as holding nearly nothing.
    ///
    /// [`Run::note_peak`] samples it, [`Run::working_now`] is the sum
    /// sampled, and the doc comment on `working_now` carries the
    /// argument that the sampling sites contain the true maximum.
    peak: u64,
    /// What an inline recovery record computed in place holds while it is
    /// encoded (`rr5::in_place_bytes`), and zero otherwise.
    recovery_scratch: u64,
    /// The worker team's batch now being WRITTEN: member `team_from + i`'s
    /// packed bytes and unpacked digest at `team_ready[i]`, or the error
    /// its pull ended in, each taken as the writer reaches that member
    /// (`Run::take_prepared`). Empty outside a team walk.
    team_ready: Vec<Option<Result<Prepared>>>,
    team_from: usize,
    /// Buffers given back by the members a team batch has written, handed
    /// to the crews again, so that a batch of a size already seen
    /// allocates nothing (spec G 7.3). Emptied (length zero) before they
    /// are kept.
    team_spare: Vec<Vec<u8>>,
    /// The batch buffers the worker team's readers are pulled into, kept
    /// between batches ([`TeamBatch`], `Run::keep_pull`).
    team_pulls: Vec<Vec<u8>>,
    /// Packed output buffers a team member is lent and gives back once
    /// written (`Run::lend_packed`), at most `Run::packed_pool_most` of
    /// capacity between them.
    packed_pool: Vec<Vec<u8>>,
    /// The capacity of the packed buffers [`Run::pool_packed`] did NOT
    /// keep since the team's round began: what the round held of the
    /// batch it wrote beyond what is now in `packed_pool`
    /// (`Run::walk_team`'s high point).
    packed_dropped: u64,
    /// The most members and input bytes one team batch takes
    /// (`Run::team_batch`), set when the team walk starts.
    team_batch: (usize, u64),
    /// The rest of what the team holds at a sampling instant, beyond
    /// `team_ready`: see `Run::walk_team`. Zero outside that instant.
    team_held: u64,
    /// What the worker team's crews hold between rounds (their finders,
    /// histories and parses' scratches, which they keep), so that every
    /// sample of [`Run::working_now`] states it and not only the one at a
    /// round's end: the writing thread's own members are encoded WHILE
    /// the crews run. Zero outside `Run::walk_team`.
    team_resident: u64,
    /// The most windows of one member a flush stages where no caller
    /// named a ceiling (`Run::choose_lead_depth`): as many as the engine's
    /// batch takes, unless the lead alone would not fit the policy's
    /// `working_limit` at that depth.
    lead_depth: usize,
    /// A held member's packed buffer (`Run::held_kept`), set aside while
    /// members that do not append into one are written, and handed back
    /// to the next that does (`Run::reserve_held`).
    held_spare: Vec<u8>,
    /// Whether [`Run::packed`] is that held buffer now.
    packed_held: bool,
    /// The most bytes ever written into the held buffer: what of it is
    /// resident. Its reserve beyond that is never written, so neither
    /// glibc's resident set nor macOS's footprint counts it, and stating
    /// the capacity read a member's full bound where its bytes packed to a
    /// fraction of it.
    held_touched: usize,
    /// Which members spec G 3.8.3's samples said to STORE, by index, so
    /// that a header built for any member reads that member's own verdict
    /// (`Run::member_stored`). Decided as each member is reached
    /// (`Run::sample_member`); false until then and for every member the
    /// rule does not sample.
    stored_by_sample: Vec<bool>,
    /// Which members have had spec G 3.8.3's verdict taken already: by
    /// the worker team as it plans a batch (`Run::plan_batch`), which may
    /// have pulled a reader member whole, so that the writer does not
    /// sample it again from a reader with nothing left in it.
    sampled: Vec<bool>,
    /// A reader member of a SOLID run that a batch may stage, pulled whole
    /// to be sampled where no flush was running to sample it beside
    /// (`Run::sample_solid`), which the samples then COMPRESS: the batch
    /// that starts at it stages these bytes in place of a second pull.
    pulled_ahead: Option<(usize, Vec<u8>)>,
    /// The judges a SOLID run's verdicts are taken by, kept between them
    /// (`store::Judges`). None is built outside a solid run, or under a
    /// caller's ceiling.
    judges: store::Judges,
    /// The head of a reader member of a SOLID run LONGER than a window,
    /// pulled by the writing thread beside the flush before it as far as
    /// its vote's leading samples (`pull_ahead`), with how many of them
    /// compress, until the writer reaches that member and takes it as its
    /// own held head (`Run::prefix`). The member is marked sampled only
    /// where those samples settled the vote.
    head_ahead: Option<(usize, Prefix, usize)>,
    /// The error that head's pull ended in, which its member returns when
    /// the writer reaches it.
    head_failed: Option<(usize, Error)>,
    /// The head of the READER member being written, held from its
    /// sampling until the path it chose has read it back
    /// (`store::Prefix`).
    prefix: Prefix,
    /// The reader member whose end `Run::pull_whole` already checked, so
    /// that `Run::check_payload_end` does not read it a second time when
    /// the member is written.
    end_checked: Option<usize>,
    /// How many bytes the run's encoders parse at once where a CALLER'S
    /// budget holds them (`Run::chosen_hold`), or `None`: the default
    /// policy, and a budget wide enough for the unheld lead and team.
    hold: Option<usize>,
    /// How many of the lead's tree blocks are parsed at once where a
    /// CALLER'S budget holds them (`Run::chosen_parses`), or `None`.
    parses: Option<usize>,
    /// How many blocks the lead's chains link ahead of their oldest parse
    /// where an ENVIRONMENT'S cap binds and no plan fits it
    /// (`Run::parses_under_cap`), or `None`: every other run.
    chain_width: Option<usize>,
    /// The largest member the worker team takes (`Run::choose_team_most`),
    /// [`TEAM_MEMBER_MOST`] until the team walk chooses.
    team_most: u64,
    /// The LARGE-MEMBER LANE (`Run::choose_large_lane`): the largest
    /// member its crews take, or zero where there is none, and how many of
    /// the team's crews are its crews.
    large_most: u64,
    large_crews: usize,
    /// The small crews beside the lane's, where it runs.
    small_crews: usize,
    /// The largest member the lane's crews take where the lane reaches
    /// past one window, which a batch grows by a crew (`Run::team_batch`);
    /// zero where it stays inside one.
    large_largest: u64,
    /// What the lane's crews and their batches were charged when it was
    /// chosen (`Run::choose_large_lane`).
    lane_charged: u64,
    /// What the worker team's crews are charged while `Run::walk_team`
    /// runs, zero outside it: the segment team's room is what is left
    /// beside it (`Run::segment_width`), since the crews grow into their
    /// charge while the writing thread encodes a member of its own.
    team_charged: u64,
    /// Whether this run, under a limit nobody named that sits below the
    /// floor's, takes the small named path's byte-neutral dials
    /// (`Run::choose_rung`, `Run::dial_ceiling`). False at every other
    /// policy, and where the default's own admission was chosen.
    narrow: bool,
}

/// The encoder's history span, `encode::drive`'s `SPAN_BYTES`: what
/// `Run::new` refuses a dictionary at or over, where the run is longer.
const ENCODER_SPAN_BYTES: u64 = 1 << 31;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    fn new(
        mut options: Resolved,
        members: Vec<Planned<'a>>,
        source: V,
        progress: &'p mut P,
    ) -> Result<Self> {
        let sizes = members.iter().map(|m| m.size);
        let largest = crate::carry::b_writers::rar50::write::largest_payload(sizes, options.solid);
        let dictionary = fitted_dictionary(options.dictionary, largest);
        // Refused by name, before a byte of output: a compressed RAR 5
        // write whose FITTED dictionary is 2 GiB or more over a run (the
        // largest member, or the whole set where it is solid) longer than
        // 2 GiB. The encoder's history is capped at a span of 2 GiB and a
        // slide keeps the dictionary, so there the history outgrows the
        // span its chains are sized for: a build with overflow checks
        // panicked in `Chains::wave_bytes` with part of the archive
        // written, and past 4 GiB the chains' positions, kept in 32 bits,
        // would wrap (sweep L-13, 4 Oct 2026). A dictionary of 1 GiB
        // writes any such run, and a 2 or 4 GiB one writes a run of up to
        // 2 GiB. One shape that did write is refused with the rest: a
        // non-solid member over 2 GiB held whole and encoded as one region
        // at a 2 GiB dictionary. Which path a member takes follows the
        // memory admission, and a refusal is not keyed on that.
        if !options.is_rar4()
            && options.method != 0
            && dictionary >= ENCODER_SPAN_BYTES
            && largest > ENCODER_SPAN_BYTES
        {
            return Err(refuse(
                "a dictionary of 2 GiB or more over a member or a solid set longer than 2 GiB (a dictionary of 1 GiB writes it)",
            ));
        }
        // In the PAYLOAD budget this is the whole of the rule. In the
        // FILE budget it is recomputed from where the output stands each
        // time a fragment is about to be placed (`refresh_budget`), so
        // what it starts at here is only what holds until the archive
        // head has been written.
        let budget = options.volume_size.unwrap_or(u64::MAX);
        let mut draw = Draw::new(std::mem::replace(
            &mut options.entropy,
            crate::write::Entropy::Os,
        ));
        // The header key comes AFTER the member key, so the draw order is
        // fixed and a seeded source reproduces the archive; under RAR 5 it
        // is the member key itself, one salt and one derivation for the
        // archive (`ArchiveKey::derive_with_headers`, spec K 3.7.7).
        let (key, header) = ArchiveKey::derive_with_headers(
            options.password.as_ref(),
            options.is_rar4(),
            options.encrypt_headers,
            &mut draw,
        )?;
        let (header_key, header_salt) = match header {
            Some((key, salt)) => (Some(key), salt),
            None => (None, [0u8; 16]),
        };
        let stored_by_sample = vec![false; members.len()];
        let sampled = vec![false; members.len()];
        let packed_samples = options.store_packed_samples;
        let mut run = Run {
            reference: None,
            default_locator: None,
            main_at: 0,
            options,
            progress,
            delivered: 0,
            members,
            out: Out::new(source),
            dictionary,
            budget,
            head_bytes: 0,
            volume: 0,
            buffer: vec![0u8; COPY_CHUNK],
            buffered: None,
            ahead_pool: Vec::new(),
            header_scratch: HeaderScratch::default(),
            cached: Vec::new(),
            solid_run: false,
            member_solid: false,
            draw,
            key,
            crypt: None,
            packed: Vec::new(),
            packed_seen: 0,
            unpacked_seen: 0,
            ahead: Vec::new(),
            ahead_from: 0,
            ahead_len: 0,
            ahead_digests: Vec::new(),
            ahead_input: Vec::new(),
            ahead_kept: Vec::new(),
            restage: std::collections::VecDeque::new(),
            restage_buf: Vec::new(),
            announced: 0,
            pull_failed: None,
            prefetched: std::collections::VecDeque::new(),
            prefetch_buf: Vec::new(),
            encoder: None,
            scratch: Vec::new(),
            unpacked_digest: None,
            header_iv: [0; 16],
            chains_most: 0,
            chains_split: false,
            chains_budget: 0,
            chains_drawn: 0,
            chain_seals: std::collections::VecDeque::new(),
            chains: std::collections::VecDeque::new(),
            chain_live: None,
            chain_pool: None,
            chain_now: None,
            header_iv_next: None,
            cipher_out: Vec::new(),
            header_key,
            header_salt,
            stream: StreamState::default(),
            segments: Segments::default(),
            peak: 0,
            recovery_scratch: 0,
            team_ready: Vec::new(),
            team_from: 0,
            team_spare: Vec::new(),
            team_pulls: Vec::new(),
            packed_pool: Vec::new(),
            packed_dropped: 0,
            team_batch: (TEAM_BATCH_MOST, TEAM_BATCH_BYTES),
            team_held: 0,
            team_resident: 0,
            lead_depth: usize::MAX,
            held_spare: Vec::new(),
            packed_held: false,
            held_touched: 0,
            end_checked: None,
            stored_by_sample,
            sampled,
            pulled_ahead: None,
            judges: store::Judges::new(packed_samples),
            head_ahead: None,
            head_failed: None,
            prefix: Prefix::default(),
            hold: None,
            parses: None,
            chain_width: None,
            team_most: TEAM_MEMBER_MOST,
            large_most: 0,
            large_crews: 0,
            large_largest: 0,
            lane_charged: 0,
            team_charged: 0,
            small_crews: 0,
            narrow: false,
        };
        // Before anything is planned from the members' payloads.
        run.vote_whole_members()?;
        run.hold = run.chosen_hold();
        note_chosen_hold(run.hold);
        run.parses = run.chosen_parses();
        Ok(run)
    }

    fn report(&self) -> WriteReport {
        #[cfg(feature = "bench-internals")]
        if std::env::var_os("RARKIT_TEAM_SAY").is_some() {
            PEAK_SAID.with(|said| eprintln!("rarkit team: {}", said.borrow()));
        }
        // The mark carried across the run, and one last sample, so that
        // a run which somehow reached no sampling site at all still
        // reports what it is holding now rather than zero.
        let peak_working_memory = self.peak.max(self.working_now());
        WriteReport {
            volumes: self.out.volumes(),
            bytes: self.out.total(),
            held_volume_bytes: self.out.held_peak(),
            peak_working_memory,
            // The ceiling report: the write is never refused for a
            // ceiling it cannot keep, so this is how a caller learns that
            // it was passed. A caller who named no ceiling is told
            // nothing, because there is nothing to tell.
            ceiling_exceeded_by: self.caller_ceiling().and_then(|ceiling| {
                let over = peak_working_memory.saturating_sub(ceiling);
                (over > 0).then_some(over)
            }),
        }
    }

    /// The whole run.
    fn walk(&mut self) -> Result<()> {
        // Before a byte is written: which admission this run takes under
        // a small limit nobody named.
        self.choose_rung()?;
        // And whether a ceiling the caller named, and asked to have kept,
        // can be kept at all.
        self.refuse_over_named_ceiling()?;
        // A run on the small path's dials under a ceiling the caller asked
        // to have kept runs no wider than `NARROW_WIDTH_MOST`
        // (`Run::narrow_width`); held for the rest of the walk.
        let _narrow_width = self.narrow_width().map(|width| {
            self.options.workers = Some(width);
            width::enter(Some(width))
        });
        if self.options.reference_layout() {
            self.reference = Some(self.plan_reference());
        }
        self.default_locator = self.default_locator_width();
        // An output that can be read back gives the record the volume
        // itself to be computed from, so no copy is kept once a volume may
        // pass the copy's limit (spec G 3.11, `Run::recovery_reads_back`).
        if self.options.recovery_percent.is_some() && !self.recovery_reads_back() {
            self.out.keep_a_copy(self.tee_reserve());
        }
        self.out.start_volume()?;
        self.write_archive_head(true)?;
        self.write_comment()?;
        // A comment is written once, into the first volume, and cannot be
        // split; neither can the volume's own head. If the cap cannot
        // hold them and the end block, no run can honour it, and the
        // caller learns that here rather than being handed an oversized
        // volume.
        self.check_volume_fits()?;

        self.choose_lead_depth();
        self.choose_team_most();
        self.choose_large_lane();
        let width = self.team_width();
        if width >= 2 {
            self.walk_team(width)?;
        } else {
            self.choose_chains();
            if self.chains_most > 0 {
                self.walk_chains()?;
            } else {
                for index in 0..self.members.len() {
                    self.write_member(index)?;
                }
            }
        }

        self.write_quick_open()?;
        self.write_recovery()?;
        self.write_end(false)?;
        self.close_volume()
    }

    // ---- members --------------------------------------------------------

    fn write_member(&mut self, index: usize) -> Result<()> {
        let size = self.members[index].size;
        let directory = self.members[index].is_directory;
        // A member the samples judge is taken up before its vote, which is
        // where a member-at-a-time walk first pulls it (`Run::announce`).
        let pulls = !directory && size > 0;
        if pulls && self.may_sample(index) {
            self.announce(index)?;
        }

        // Spec G 3.8.3: stored or compressed is decided FIRST, because the
        // header's method and dictionary say which, and every header this
        // member is given below, the one the volume budget is fitted with
        // included, has to say it.
        self.sample_member(index)?;

        // **A member that would START in a new volume opens that volume
        // HERE, before anything is compressed.** The fragment walk below
        // would otherwise open it part way through, after the encoder had
        // already been told whether this member continues the one before
        // it, and a volume boundary ENDS a solid run (spec G 3.9): the
        // encode would carry the history and the header, built after the
        // boundary, would say the member is not solid. A decoder told
        // that resets its window and the first match into the history is
        // out of range. Found by `write_volumes`, which is exactly the
        // shape it looks for: a two member solid RAR 3 set whose first
        // member's packed bytes fill a volume to the byte.
        // Every member's header has to fit the FILE cap, including the
        // ones the fragment walk below never sees.
        self.fit_member_header(index, !directory && size > 0)?;
        if self.options.volume_set() && !directory && size > 0 {
            self.refresh_budget();
            let least = if self.options.password.is_some() {
                CIPHER_BLOCK as u64
            } else {
                1
            };
            if self.budget < least {
                self.next_volume()?;
            }
        }
        // Every other member with a payload is taken up here, once the
        // volume it starts in is open.
        if pulls {
            self.announce(index)?;
        }

        // The compressed path: spec G decides WHAT to compress and with
        // which parameters, and spec H3's encoders compress (section 1.2).
        // The packed bytes are produced here, before the header that
        // describes them, because the header's packed size field IS their
        // length; the fragment walk below then cuts THEM where a volume
        // fills, exactly as it cuts a stored member's own bytes.
        self.unpacked_digest = None;
        // **Every path through this member starts with `packed` empty**,
        // including the streamed one, which returns below before the
        // assignments that used to be the only thing emptying it. Left
        // full, the PREVIOUS member's packed bytes would be counted by
        // `Run::working_now` as held at the same time as this member's,
        // and the run would report a peak it never reached. The
        // allocation stays where it is; only the length goes. A held
        // buffer (`Run::held_kept`) is kept for the next held member, and
        // stated by what was ever written into it (`Run::held_touched`):
        // let go and reserved again a member at a time, macOS 27.0 kept the
        // freed blocks in the process's footprint, 869 MiB against 525 of
        // live heap on bin4g at `-m3 -mt32` (an Apple M3 Mac, counted with a
        // scratch allocator).
        if self.packed_held {
            self.held_touched = self.held_touched.max(self.packed.len());
        }
        self.packed.clear();
        // A member that will not append into a held buffer hands `packed`
        // to the encoder, which swaps it in as its own output and returns a
        // small one, and a held buffer went that way: it stayed in the
        // engine, stated nowhere, while the next held member reserved
        // another, two buffers of about 90 MiB at bin4g's peak at `-m3
        // -mt1` (an Apple M3 Mac, counted with a scratch allocator). It waits
        // aside instead, stated (`Run::working_now`), for the next.
        if self.packed_held && !self.held_kept(index) {
            self.held_spare = std::mem::take(&mut self.packed);
            self.packed_held = false;
        }
        // Taken HERE, where the run's state is the one the encode below
        // is about to use, and held for every fragment of this member
        // (`Run::member_solid`).
        self.member_solid = self.options.solid && self.solid_run && !self.member_stored(index);
        // A member whose packed output the writer will NOT hold takes
        // its own walk, which cuts the encoder's chunks into fragments
        // as they arrive (`Run::write_member_streamed`).
        if self.streams_packed(index) {
            return self.write_member_streamed(index);
        }
        if !directory && size > 0 && !self.member_stored(index) {
            self.compress(index)?;
            // What the next batch's estimate is built on.
            self.packed_seen = self.packed_seen.saturating_add(self.packed.len() as u64);
            self.unpacked_seen = self.unpacked_seen.saturating_add(size);
        }
        // What the fragment walk below cuts: a stored member's own bytes,
        // or the packed bytes the encoder returned.
        let stream = if self.packed.is_empty() {
            size
        } else {
            self.packed.len() as u64
        };

        // One cipher per member, with its initialisation vector drawn
        // here: one draw per member, in `add` order (spec G 3.13).
        self.crypt = if index < self.chains_drawn {
            let seal = self
                .chain_seals
                .pop_front()
                .expect("a member drawn ahead with nothing kept for it");
            debug_assert_eq!(seal.index, index);
            self.header_iv_next = seal.header_iv;
            seal.crypt
        } else {
            // Drawn here, as always: a later draw ahead starts after it.
            if self.chains_most > 0 {
                self.chains_drawn = index + 1;
            }
            if directory {
                None
            } else {
                MemberCrypt::new(&self.key, &mut self.draw)?
            }
        };

        if directory || size == 0 {
            let digest = self.stored(self.member_digest_empty(index));
            let mut scratch = std::mem::take(&mut self.header_scratch);
            self.member_header(index, Fragment::Whole, 0, digest, &mut scratch);
            let written = self.write_header_and_cache(index, &scratch.bytes, 0);
            self.header_scratch = scratch;
            written?;
            self.crypt = None;
            // One report per member, even an empty one, so a caller
            // counting members sees every one of them.
            return self.progress.output(self.delivered);
        }

        // The payload is pulled once, whatever shape it is in, and cut only
        // where a volume fills.
        let mut written = 0u64;
        let mut first = true;
        let mut whole = self.whole_digest(index);
        if whole.is_none() {
            whole = self.digest_before_header(index, size)?;
        }
        // **Each of these runs only when its answer is used.** A member
        // that fits one fragment used to be hashed TWICE over the same
        // bytes - once as the fragment and once as the whole - and the
        // fragment's answer was then thrown away, which on a 128 MiB
        // stored member is a whole extra pass at memory bandwidth beside
        // the copy itself. The whole member's is needed when the header
        // does not already carry it, or when a caller stated a CRC32 for
        // the writer to check; a fragment's is needed only on a fragment
        // that is not the last, because the last carries the member's
        // (spec G 3.10.2).
        let want_whole = whole.is_none() || self.declared_crc32(index).is_some();
        let mut whole_running = self.copy_digest();
        let encrypting = self.crypt.is_some();

        while written < stream {
            self.refresh_budget();
            if self.budget == 0 || (encrypting && self.budget < CIPHER_BLOCK as u64) {
                let left = stream - written;
                if self.budget < left {
                    self.next_volume()?;
                }
            }
            let mut room = self.budget.min(stream - written);
            // In the FILE budget the fragment's own header is paid for
            // out of the same cap as its payload, and the header's length
            // follows the packed size it declares, so the two are solved
            // together rather than one after the other.
            if self.options.volume_file_size.is_some() {
                room = self.fit_header(index, written, stream, first, room);
                if room == 0 {
                    // Not even a header and one byte fit in what is left
                    // of this volume. A fresh volume has the whole cap,
                    // which `Writer::new`'s floor has already shown can
                    // hold a header and a byte, so this cannot loop.
                    if written == 0 && self.out.position() == self.head_bytes {
                        return Err(refuse(
                            "a volume file size too small for this member's own header",
                        ));
                    }
                    self.next_volume()?;
                    self.refresh_budget();
                    room = self.fit_header(
                        index,
                        written,
                        stream,
                        first,
                        self.budget.min(stream - written),
                    );
                    if room == 0 {
                        return Err(refuse(
                            "a volume file size too small for this member's own header",
                        ));
                    }
                }
            }
            let mut last = written + room == stream;
            if encrypting && !last {
                // A fragment that is not the last holds whole cipher
                // blocks, so the chain never carries across a volume.
                room -= room % CIPHER_BLOCK as u64;
                if room == 0 {
                    self.next_volume()?;
                    room = self.budget.min(stream - written);
                    // **The fresh volume pays for this fragment's header
                    // too.** In the FILE budget the room is what is left
                    // of the cap once the header is in it, and taking the
                    // whole budget here wrote the header on top of a full
                    // volume: the volume ran past its cap by the header's
                    // length (spec G 3.10.1: never).
                    if self.options.volume_file_size.is_some() {
                        room = self.fit_header(index, written, stream, first, room);
                    }
                    last = written + room == stream;
                    if !last {
                        room -= room % CIPHER_BLOCK as u64;
                    }
                    // A fresh volume that cannot take one cipher block of
                    // this member never will, so the run says so instead
                    // of writing fragments of no bytes for ever.
                    if room == 0 {
                        return Err(refuse(
                            "a volume budget too small for one cipher block of this member",
                        ));
                    }
                }
            }
            let fragment = match (first, last) {
                (true, true) => Fragment::Whole,
                (true, false) => Fragment::First,
                (false, true) => Fragment::Last,
                (false, false) => Fragment::Middle,
            };
            let packed = if encrypting && last {
                padded_len(room)
            } else {
                room
            };

            // The checksum a fragment carries is its OWN except on the
            // last, which carries the whole member's (spec G 3.10.2). A
            // RAR 5 encrypted fragment that is not the last carries the
            // plain checksum of its CIPHERTEXT (spec K 3.7.6), which exists
            // only once the copy has enciphered it, so its header is laid
            // down with a placeholder and corrected.
            let cipher_fragment = !last
                && self
                    .crypt
                    .as_ref()
                    .is_some_and(MemberCrypt::fragments_digest_ciphertext);
            let known = if last {
                whole
            } else if cipher_fragment {
                None
            } else {
                self.fragment_digest(index, written, room)
            };
            // A header laid down before its checksum is known carries a
            // placeholder of the right KIND, so that the corrected header
            // is exactly as long (spec G 3.7.2).
            let laid = known.or_else(|| self.placeholder_digest(index));
            // One set of buffers for BOTH the header laid down here and
            // the correction below: the first is out on the wire by the
            // time the second is built, and all that is still wanted of
            // it is its length (spec G 3.7.2 and 7.3).
            let mut scratch = std::mem::take(&mut self.header_scratch);
            self.member_header(
                index,
                fragment,
                packed,
                self.stored_as(last, laid),
                &mut scratch,
            );
            if known.is_none() {
                self.out.begin_hold();
            }
            let header_at = self.write_header(&scratch.bytes)?;
            let header_len = scratch.bytes.len();

            let mut fragment_running = self.copy_digest();
            if self.chain_now.is_some()
                || self
                    .chains
                    .front()
                    .is_some_and(|chain| chain.index == index)
            {
                // The fragment's own checksum is over its ciphertext (spec
                // K 3.7.6), taken here as it is written.
                let fragment = (!last).then_some(&mut fragment_running);
                if let Some(digest) = self.copy_chain(index, room, packed, fragment, last)? {
                    whole_running = digest;
                }
            } else {
                let (fragment_digest, whole_digest) = (!last, want_whole);
                self.copy_payload(
                    index,
                    written,
                    room,
                    stream,
                    fragment_digest.then_some(&mut fragment_running),
                    whole_digest.then_some(&mut whole_running),
                )?;
            }
            if last {
                self.flush_cipher()?;
            }

            if known.is_none() {
                let digest = if last {
                    let value = whole_running.finish();
                    whole = Some(value);
                    value
                } else {
                    fragment_running.finish()
                };
                self.member_header(
                    index,
                    fragment,
                    packed,
                    self.stored_as(last, Some(digest)),
                    &mut scratch,
                );
                debug_assert_eq!(scratch.bytes.len(), header_len);
                self.correct_header(header_at, &scratch.bytes)?;
            }
            if fragment == Fragment::Whole {
                self.cache_header(index, header_at, &scratch.bytes, packed);
            }
            self.header_scratch = scratch;

            self.budget -= packed.min(self.budget);
            written += room;
            first = false;
        }

        // A solid run continues from here: the next member's history is
        // this one's. A STORED member neither starts a run nor ends one
        // (spec G 3.9), and no member is compressed until spec H3's
        // encoders land, so this is the whole of the run's state today.
        if !self.member_stored(index) {
            self.solid_run = true;
        }

        if let Some(expected) = self.declared_crc32(index) {
            // A COMPRESSED member's promise is about its UNPACKED bytes,
            // and what passed the copy above is the packed ones.
            let computed = self
                .unpacked_digest
                .unwrap_or_else(|| whole_running.finish());
            if !digest_matches(computed, expected) {
                return Err(Error::new(ErrorKind::Corrupt(Corruption::Checksum))
                    .with_member(self.members[index].name));
            }
        }
        self.check_payload_end(index)?;
        self.crypt = None;
        self.progress.output(self.delivered)
    }

    /// Compresses one member through spec H3's encoder (section 1.2).
    ///
    /// **This package decides and does not compress.** What it hands down
    /// is the level's search effort, the dictionary of section 3.8.1 and
    /// the algorithm version; what comes back is the member's packed
    /// bytes and nothing else - no header, no checksum, no volume
    /// boundary, all of which are this package's.
    ///
    /// Three shapes reach the encoder and only one of them is a single
    /// call over the member's own slice:
    ///
    /// - a NON-SOLID member whose bytes are in memory is encoded from
    ///   that slice, borrowed and never copied, which is the common case
    ///   and the fast one, and it is what the DEFAULT keeps: the rule was
    ///   narrowed on 20 Sep 2026 so that a member of a non-solid
    ///   VOLUME SET stands this shortcut aside only where the caller's own
    ///   memory ceiling would not survive holding the member whole
    ///   (`Run::over_ceiling`), because the shortcut is what gives the
    ///   default its lowest wall and the writer spends memory freely when
    ///   no ceiling was named;
    /// - a member from a READER is encoded a WINDOW at a time (spec G
    ///   3.7.3), each window carrying the one before it as history, so
    ///   the member's input is never held;
    /// - a member of a SOLID set is the same walk, with the history
    ///   carried from the member BEFORE it (spec G 3.9 and spec H3
    ///   section 4, whose erratum of 19 Sep 2026 names exactly this
    ///   state). Nothing else is carried: every member of a solid set
    ///   begins its own block chain with a table carrying block, which is
    ///   what a fresh `encode_region` call emits.
    fn compress(&mut self, index: usize) -> Result<()> {
        // A member the worker team already encoded is taken from it.
        if let Some(taken) = self.take_prepared(index) {
            return taken;
        }
        self.ensure_encoder();
        let solid = self.options.solid;
        // **THE PACKED BUFFER IS NOT RESERVED, and that is a measured
        // decision rather than an omission.** Reserving it to
        // `Run::packed_bound` once a run was the 21 Sep 2026 decision's second half and
        // it was built, measured and then withdrawn. On macOS 27.0 it
        // makes `g/create/rar5/m3/vol+rr` FLAT over 25 rounds in one
        // process, +8.6 MiB against +286.6, and makes
        // `g/create/rar5/m3` WORSE by about 171 MiB over the same 22
        // extra rounds, which is 7.8 MiB a round. Three repeats either
        // side, ranges non-overlapping, one binary against itself across
        // one knob.
        //
        // That is a trade between two legs and no specification says
        // which to prefer, so it is left open rather than chosen
        // here. It also
        // CORRECTS the sentence in `Out::keep_a_copy` that an
        // over-reserve costs address space and not memory: for this
        // buffer on macOS 27.0 the retention tracked the RESERVED size
        // and not the length touched.
        // UNDER A CALLER'S CEILING the held member's packed buffer is
        // reserved once, to its bound, rather than grown to it. Grown by
        // appends it doubled to a capacity up to twice the member (32 MiB
        // for mixednoise's 20 MiB member), and each block it outgrew was
        // freed at a size macOS 27.0's allocator keeps RESIDENT in its
        // large-block cache: 30 MiB of them on that member, at -m5 -mm96
        // (the -m4 and -m5 memory work). At the
        // default policy the buffer is grown, as the note above says why.
        self.reserve_held(index);
        if !solid
            && !self.streams_packed(index)
            && matches!(self.members[index].payload, Payload::Bytes(_))
        {
            let Run {
                members,
                encoder,
                packed,
                ..
            } = self;
            let Payload::Bytes(data) = &members[index].payload else {
                unreachable!("the branch above tested for Payload::Bytes")
            };
            let data: &[u8] = data;
            packed.clear();
            let before = packed.capacity();
            encoder
                .as_mut()
                .expect("the encoder was just built")
                .region(data, 0, true, packed);
            note_packed_capacity(before, packed.capacity());
            // The member's packed bytes are complete, which is this
            // buffer's high point for the member.
            self.note_peak();
            return Ok(());
        }
        // A member a BATCH already encoded is taken from it; otherwise a
        // batch starting here is encoded now, and this member is its
        // first. Both leave the member's own packed bytes in
        // `Run::packed` and nothing else changes below.
        if self.take_ahead(index) {
            return Ok(());
        }
        if let Some(error) = self.take_pull_failed(index) {
            return Err(error);
        }
        if self.batch_solid(index) {
            assert!(
                self.take_ahead(index),
                "a batch holds the member it was built for"
            );
            return Ok(());
        }
        // The batch's first member's own pull failed: its reader is spent.
        if let Some(error) = self.take_pull_failed(index) {
            return Err(error);
        }
        self.compress_streaming(index)
    }

    /// Start member `index`'s own run in the run's encoder, from no
    /// history, where the member is fed to it a window at a time: the
    /// encoder takes the plan the member's class gives it
    /// (`encode::drive::Engine::start_member`, SPEC-H3 8.1).
    ///
    /// The class is read from the member's HEAD, its first megabyte: from
    /// the slice for bytes in memory, and for a READER from the head the
    /// store rule's samples left held, pulled on to a megabyte where they
    /// settled their vote short of it (`store::Prefix::head`). It is held
    /// with the rest and read back by the member's first windows, so the
    /// reader is still read once, in order. Nothing is read or pulled
    /// where no class is taken: below level 5, under the options that keep
    /// one finder, and for a member under a megabyte.
    ///
    /// A SOLID run's first member is started here too, and its class is the
    /// run's (`encode::drive::Plan::solid_run`); the members after it are
    /// not started, and follow it. A run that a batch of small members
    /// starts takes its class there (`Run::batch_solid`).
    fn start_member_run(&mut self, index: usize) -> Result<()> {
        let size = self.members[index].size;
        // The charge's rule (`Run::reads_class`) and the encoder's own are
        // one rule, kept in step here.
        debug_assert_eq!(
            self.encoder
                .as_ref()
                .is_some_and(|encoder| encoder.reads_head(size)),
            self.reads_class() && size >= class::HEAD_BYTES as u64,
            "the charge reads a head where the encoder does"
        );
        let Run {
            members,
            encoder,
            prefix,
            ..
        } = self;
        let encoder = encoder.as_mut().expect("the encoder was built");
        if !encoder.reads_head(size) {
            encoder.start_member(&[], size);
            return Ok(());
        }
        match &mut members[index].payload {
            Payload::Bytes(data) => encoder.start_member(data, size),
            Payload::Reader { reader, .. } => {
                let span = usize::try_from(size.min(store::PREFIX_BYTES as u64))
                    .expect("the prefix is at most 32 MiB");
                let head = prefix.head(index, &mut **reader, class::HEAD_BYTES, span)?;
                encoder.start_member(head, size);
            }
        }
        // The head is at its fullest here.
        self.note_peak();
        Ok(())
    }

    /// Tell the caller the writer has TAKEN UP member `index`
    /// (`Progress::member_started`, spec G 3.13's "a member starting"),
    /// once for each member with a payload to pull, in the order written.
    ///
    /// It is made where a member-at-a-time walk makes that member's first
    /// pull: before the vote of a member spec G 3.8.3 samples
    /// (`Run::sample_member` pulls its head), and for every other member
    /// once the volume it starts in is open. A caller once read that
    /// moment off the first read of the member's reader, and a batch or
    /// the worker team pulls readers AHEAD of the writer, so in a volume
    /// set a boundary reported against the member last pulled landed on
    /// the wrong member; this call is the member the writer is on, whoever
    /// pulled it and whenever.
    fn announce(&mut self, index: usize) -> Result<()> {
        if index < self.announced {
            return Ok(());
        }
        self.announced = index + 1;
        self.progress.member_started(index)
    }
}
