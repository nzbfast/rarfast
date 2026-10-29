//! The worker team's walk: batches of members packed by crews on the pool
//! while the writing thread places what they packed, in `add` order.

use super::*;

/// What one parse block is allowed to add to a member's packed size when
/// the encoder cannot compress it: the encoder's own figure,
/// `encode::drive::BLOCK_ROOM_BYTES`.
///
/// An allowance, in the same spirit as [`BATCH_HEADER_ROOM`]: it bounds
/// the packed size a member the writer has not encoded yet could reach,
/// and it decides which side of a ceiling `Run::held_whole_bytes` lands
/// on and what a held member's buffer is reserved to. Spec G 3.5 measured
/// 14 fragments of structureless bytes at level 3, 2 of them larger packed
/// than unpacked by at most 48 bytes, and this was 64 a block until 28 Sep
/// 2026, when 4 MiB of xorshift output came out about 142 bytes a block
/// over at every level and 20 MiB of SHA-256 output outgrew a buffer
/// reserved to the old figure (the -m4 and -m5
/// memory work).
pub(super) const STORED_BLOCK_ROOM: u64 = crate::encode::drive::BLOCK_ROOM_BYTES as u64;

/// The most members one team batch holds. With [`TEAM_BATCH_BYTES`] it
/// bounds what the team holds, and it is wide enough that the crews'
/// last members of a batch, finishing at different times, are a small
/// share of the batch.
pub(super) const TEAM_BATCH_MOST: usize = 512;

/// The least capacity [`Run::lend_packed`]'s pool keeps between batches;
/// it keeps twice a team batch's input where that is more
/// (`Run::packed_pool_most`). The name and shape are the solid create
/// work's pool, which the
/// crews share by design: one pool.
pub(super) const PACKED_POOL_BYTES: usize = 16 << 20;

/// The most input one team batch takes, in unpacked bytes: what bounds a
/// batch's packed output (at most this and a stored block's room a
/// member) and, for reader members, what is pulled ahead.
pub(super) const TEAM_BATCH_BYTES: u64 = 4 << 20;

/// What one team batch adds per crew, in input bytes and in members,
/// where no caller named a memory ceiling (`Run::team_batch`): the batch
/// is at least [`TEAM_BATCH_BYTES`] and [`TEAM_BATCH_MOST`], and grows
/// with the team past them.
///
/// **Why the batch follows the width.** A round of `Run::walk_team` ends
/// when its slowest crew does, and a crew's unit is a member of up to
/// [`TEAM_MEMBER_MOST`]. At a fixed 4 MiB a team of seventeen crews was
/// handed about one 256 KiB member apiece a round, so every round waited
/// on its largest member while the rest of the team sat idle: counted 28
/// Sep 2026 on 5,000 small members at level 1, 18 cores, 0.098 s wall
/// at 4 MiB and 0.074 s at a MiB a crew, the same bytes.
/// Under a caller's
/// ceiling the batch stays at its floor, which is what that ceiling's
/// share (`Run::beside_team_bytes`) was measured with.
pub(super) const CREW_BATCH_BYTES: u64 = 1 << 20;

pub(super) const CREW_BATCH_MEMBERS: usize = 32;

/// The most capacity the team's kept buffers hold between them, under a
/// caller's ceiling and at the default policy (`Run::keep_spare`): a
/// batch's pulled input and a batch's packed output, which is what one
/// round gives back.
pub(super) const TEAM_SPARE_BYTES: u64 =
    2 * (TEAM_BATCH_BYTES + TEAM_BATCH_MOST as u64 * STORED_BLOCK_ROOM);

/// One member as a crew receives it.
pub(super) enum TeamInput<'a> {
    /// A `Payload::Bytes` member's own bytes, borrowed.
    Slice(&'a [u8]),
    /// A reader member's bytes, pulled whole by the writing thread into
    /// its batch's one buffer (`Run::pull_into`): where they lie in it.
    Pulled(std::ops::Range<usize>),
    /// A member that carries no bytes, a directory or an empty file, which
    /// a batch passes over (`Run::plan_batch`) and the writing thread
    /// writes as it always did; no crew sees it.
    Nothing,
}

/// One batch of the worker team as the writing thread plans it
/// (`Run::plan_batch`): each member's input in `add` order, and the ONE
/// buffer its reader members were pulled into.
///
/// One buffer a batch, kept for the batch after next (`Run::team_pulls`),
/// and never one a member: a buffer a member was allocated, zero-filled
/// and first touched by the writing thread for every member it pulled,
/// which on the 4 GiB set of real binaries at level 1 was about half of
/// what that thread did between rounds (counted 1 Oct 2026 on
/// a Zen 4 rental). The buffer's
/// length is its high-water mark and is never cut back, so a member read
/// into bytes an earlier batch touched costs neither.
pub(super) struct TeamBatch<'a> {
    pub(super) inputs: Vec<Result<TeamInput<'a>>>,
    pub(super) pulled: Vec<u8>,
}

/// What a crew hands back for one member: its packed bytes and the
/// digest of its unpacked bytes.
pub(super) struct Prepared {
    pub(super) packed: Vec<u8>,
    pub(super) digest: Digest,
}

/// What every member of a run is packed by, the same for all of them.
#[derive(Clone, Copy)]
pub(super) struct PackRule {
    /// `Run::window_bytes`.
    pub(super) window: usize,
    pub(super) checksum: ChecksumKind,
    /// The threads a crew's digest may use, its own included: ONE, since
    /// the crew is a helper already and its pool is full of its fellows
    /// (`Run::digest_threads`). A crew's member is at most a
    /// window, and a BLAKE2sp team engages only on a batch worth one.
    pub(super) digest_threads: usize,
    /// `Run::staged_depth`: how many windows of a member above one window
    /// the walk stages a flush.
    pub(super) depth: usize,
    /// The history's slack, in dictionaries, the walk encodes such a
    /// member under (`Run::streamed_slack_multiple`).
    pub(super) slack: usize,
}

/// Encodes one member of a non-solid run WITH THE CALL THE
/// MEMBER-AT-A-TIME WALK MAKES FOR IT, into `packed` (emptied first).
///
/// - A slice payload is `Run::compress`'s one-region shortcut, and its
///   digest is `Run::whole_digest`'s.
/// - A reader's bytes are `Run::compress_streaming`'s windowed encode from
///   a fresh history, a window at a time, with the digest taken as the
///   windows pass. A region and a chain of windows are not the same packed
///   stream (`Run::streams_packed` says where that was measured), so the
///   two shapes are kept apart here exactly as they are there.
pub(super) fn pack_member(
    encoder: &mut Encoder,
    input: &TeamInput<'_>,
    pulled: &[u8],
    rule: PackRule,
    mut packed: Vec<u8>,
) -> Prepared {
    packed.clear();
    match input {
        TeamInput::Slice(data) => {
            encoder.region(data, 0, true, &mut packed);
            Prepared {
                packed,
                digest: slice_digest(data, rule.checksum, rule.digest_threads),
            }
        }
        // A member of one window is a run of its own in one chunk, which
        // is the windowed encode's first and only call; what the whole
        // run form saves is the history a longer run would need room for.
        TeamInput::Pulled(range) if range.len() <= rule.window => {
            let data = &pulled[range.clone()];
            let mut digest = new_running(rule.checksum, rule.digest_threads);
            digest.update(data);
            encoder.whole_run(data, &mut packed);
            Prepared {
                packed,
                digest: digest.finish(),
            }
        }
        TeamInput::Nothing => unreachable!("no crew is handed a member without bytes"),
        // A reader above one window (the large-member lane's, where it
        // reaches past a window): the walk's own calls in the walk's own
        // order, from a fresh history under the walk's slack, its windows
        // staged as the walk stages them (`encode_stretch`, the member as
        // one stretch that starts and ends it) or handed over one at a
        // time where the walk stages none. The crew's slack is put back,
        // as the walk puts the run's own encoder's back.
        TeamInput::Pulled(range) => {
            let data = &pulled[range.clone()];
            let mut digest = new_running(rule.checksum, rule.digest_threads);
            digest.update(data);
            if rule.depth > 1 {
                let whole = Stretch {
                    kept: 0,
                    base: 0,
                    last: true,
                    effort: None,
                };
                encode_stretch(
                    encoder,
                    data,
                    whole,
                    rule.window,
                    rule.depth,
                    rule.slack,
                    &mut packed,
                );
            } else {
                encoder.start_member(data, data.len() as u64);
                encoder.set_slack_multiple(rule.slack);
                let mut at = 0;
                loop {
                    let room = (data.len() - at).min(rule.window);
                    let last = at + room == data.len();
                    encoder.chunk(&data[at..at + room], last, &mut packed, at as u64);
                    at += room;
                    if last {
                        break;
                    }
                }
            }
            encoder.set_slack_multiple(crate::encode::drive::HISTORY_SLACK_MULTIPLE);
            Prepared {
                packed,
                digest: digest.finish(),
            }
        }
    }
}

/// A lock that a crew's panic does not poison for the rest of the walk:
/// the panic itself is carried out of the round by the scope.
pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

// How many members this thread has written from a worker team batch
// (`Run::take_prepared`), so that a test can say the team encoded what it
// compares. Nothing in a shipped build carries it.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static TEAM_PREPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One member written from a team batch.
pub(super) fn note_team_prepared() {
    #[cfg(feature = "bench-internals")]
    TEAM_PREPARED.with(|count| count.set(count.get() + 1));
}

/// How many members this thread has written from a worker team batch
/// since [`reset_team_prepared`]. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn team_prepared() -> usize {
    TEAM_PREPARED.with(std::cell::Cell::get)
}

/// Starts the count in [`team_prepared`] again from zero.
#[cfg(feature = "bench-internals")]
pub(crate) fn reset_team_prepared() {
    TEAM_PREPARED.with(|count| count.set(0));
    TEAM_BATCHES.with(|count| count.set(0));
    PACKED_FRESH.with(|count| count.set(0));
}

// How many members a solid batch staged from readers on this thread, and
// how many of those it staged a SECOND time, from the bytes kept, after a
// volume boundary discarded the batch they were first staged in: a test's
// way of saying that a volume set of readers was batched at all, and that
// the discard it compares across was met. Nothing in a shipped build
// carries it.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static READERS_BATCHED: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// A solid batch staged a reader member, for the second time if `again`.
pub(super) fn note_reader_batched(again: bool) {
    #[cfg(feature = "bench-internals")]
    READERS_BATCHED.with(|count| {
        let (staged, twice) = count.get();
        count.set((staged + 1, twice + usize::from(again)));
    });
    #[cfg(not(feature = "bench-internals"))]
    let _ = again;
}

/// How many reader members this thread's solid batches have staged since
/// [`reset_readers_batched`], and how many of them a second time after a
/// volume boundary. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn readers_batched() -> (usize, usize) {
    READERS_BATCHED.with(std::cell::Cell::get)
}

/// Starts the counts in [`readers_batched`] again from zero.
#[cfg(feature = "bench-internals")]
pub(crate) fn reset_readers_batched() {
    READERS_BATCHED.with(|count| count.set((0, 0)));
}

// How many crews this thread's last worker team walk ran with, so that a
// test can say which width the policy gave it. Nothing in a shipped build
// carries it.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static TEAM_CREWS: std::cell::Cell<(usize, u64, usize, u64)> =
        const { std::cell::Cell::new((0, 0, 0, 0)) };
}

/// A worker team walk of `width` crews, taking members of at most `most`
/// bytes, `large` of them the large-member lane's up to `large_most`, is
/// starting.
pub(super) fn note_team_crews(_width: usize, _most: u64, _large: usize, _large_most: u64) {
    #[cfg(feature = "bench-internals")]
    TEAM_CREWS.with(|crews| crews.set((_width, _most, _large, _large_most)));
}

// How many non-empty team batches this thread has planned, for the test
// that a batch spans directory members.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static TEAM_BATCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// How many packed buffers the pool has had to allocate fresh on this
// thread (`Run::lend_packed`), for the test that the team reuses them
// rather than allocating, regrowing and freeing one per member.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static PACKED_FRESH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The pool allocated a fresh packed buffer.
pub(super) fn note_packed_fresh() {
    #[cfg(feature = "bench-internals")]
    PACKED_FRESH.with(|count| count.set(count.get() + 1));
}

/// How many packed buffers the pool allocated fresh on this thread since
/// [`reset_team_prepared`]. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn packed_fresh() -> usize {
    PACKED_FRESH.with(std::cell::Cell::get)
}

/// One non-empty team batch was planned.
pub(super) fn note_team_batch() {
    #[cfg(feature = "bench-internals")]
    TEAM_BATCHES.with(|count| count.set(count.get() + 1));
}

/// How many non-empty team batches this thread has planned since
/// [`reset_team_prepared`]. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn team_batches() -> usize {
    TEAM_BATCHES.with(std::cell::Cell::get)
}

/// How many crews this thread's last worker team walk ran with, or zero
/// where none has. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn team_crews() -> usize {
    TEAM_CREWS.with(std::cell::Cell::get).0
}

/// The largest member this thread's last worker team walk took, in
/// bytes, or zero where none has run. This repository's tests and
/// benches only.
#[cfg(feature = "bench-internals")]
pub(crate) fn team_member_most() -> u64 {
    TEAM_CREWS.with(std::cell::Cell::get).1
}

/// The large-member lane of this thread's last worker team walk: its
/// crews and the largest member it took, or zeros.
#[cfg(feature = "bench-internals")]
pub(crate) fn team_large() -> (usize, u64) {
    let (_, _, crews, most) = TEAM_CREWS.with(std::cell::Cell::get);
    (crews, most)
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// The most members and input bytes one team batch of `width` crews
    /// takes: [`TEAM_BATCH_MOST`] and [`TEAM_BATCH_BYTES`] under a
    /// caller's ceiling, and growing past them by [`CREW_BATCH_MEMBERS`]
    /// and [`CREW_BATCH_BYTES`] a crew where no ceiling was named.
    pub(super) fn team_batch(&self, width: usize) -> (usize, u64) {
        if self.dial_ceiling().is_some() {
            return (TEAM_BATCH_MOST, TEAM_BATCH_BYTES);
        }
        // Where the lane reaches past a window, a member of its largest
        // for each of its crews beside that: a batch that held one such
        // member would leave the other crews idle.
        (
            TEAM_BATCH_MOST.max(width.saturating_mul(CREW_BATCH_MEMBERS)),
            TEAM_BATCH_BYTES
                .max((width as u64).saturating_mul(CREW_BATCH_BYTES))
                .saturating_add((self.large_crews as u64).saturating_mul(self.large_largest)),
        )
    }

    /// The most capacity the team's kept buffers hold between them
    /// (`Run::keep_spare`): [`TEAM_SPARE_BYTES`], or one batch's input
    /// where the lane reaches past a window and a batch is that much
    /// larger (the lane's charge counts it, `Run::choose_large_lane`).
    pub(super) fn team_spare_most(&self) -> u64 {
        if self.large_largest > 0 {
            TEAM_SPARE_BYTES.max(self.team_batch.1)
        } else {
            TEAM_SPARE_BYTES
        }
    }

    /// Whether writing member `index` by itself would PULL a reader: the
    /// team may not pull the members after such a member before it has.
    pub(super) fn pulls(&self, index: usize) -> bool {
        let member = &self.members[index];
        !member.is_directory && member.size > 0 && matches!(member.payload, Payload::Reader { .. })
    }

    /// The members from `start` that one team batch takes, with each
    /// one's input: a member the team takes, then the next, while the
    /// batch holds at most [`TEAM_BATCH_MOST`] members and
    /// [`TEAM_BATCH_BYTES`] of input (the first member always fits).
    ///
    /// A reader is pulled HERE, whole, by this thread and in `add` order.
    /// One whose pull fails ends the batch, with its error as its
    /// result: a member-at-a-time walk would have stopped there too, and
    /// pulled nothing after it.
    pub(super) fn plan_batch(&mut self, start: usize) -> TeamBatch<'a> {
        let mut inputs = Vec::new();
        // The batch's one buffer, and how much of it this batch has used.
        let mut pulled = self.team_pulls.pop().unwrap_or_default();
        let mut used = 0usize;
        let mut bytes = 0u64;
        let mut index = start;
        let (most, cap) = self.team_batch;
        while index < self.members.len() && inputs.len() < most {
            // A member with no bytes to encode is passed over, not a place
            // the batch ends: `rarfast a -r` adds a directory member after
            // each directory's files, and a batch that stopped at every one
            // was one directory's files and starved the crews (found in the
            // command line create path work: a tree5k shaped
            // tree of 481 directories -m3 2.17 s against 1.47 without them).
            // It stays in `add` order; the writing thread writes it.
            let member = &self.members[index];
            if member.is_directory || member.size == 0 {
                inputs.push(Ok(TeamInput::Nothing));
                index += 1;
                continue;
            }
            if !self.team_takes(index) {
                break;
            }
            let size = self.members[index].size;
            if !inputs.is_empty() && bytes.saturating_add(size) > cap {
                break;
            }
            // Spec G 3.8.3's verdict is taken HERE for a member the rule
            // samples, before the crews can encode it, and by the walk's
            // own sampler (`Run::sample_member`): bytes in memory across
            // the member, a reader over its head, pulled only as far as
            // the vote needs and held (`store::Prefix`). A member the
            // samples STORE is left to the writing thread, which writes it
            // stored from that held head and its reader, exactly as it
            // would with no team, and the batch ends before it: it is
            // never pulled whole. One that compresses is pulled into the
            // batch's buffer, the held head read back first.
            let sampling = self.may_sample(index);
            let judged = if sampling {
                let judged = self.sample_member(index);
                self.sampled[index] = true;
                judged
            } else {
                Ok(())
            };
            if judged.is_ok() && self.stored_by_sample[index] {
                break;
            }
            let input = match (judged, &self.members[index].payload) {
                (Err(error), _) => Err(error),
                (Ok(()), Payload::Bytes(data)) => Ok(TeamInput::Slice(data)),
                (Ok(()), Payload::Reader { .. }) => {
                    self.pull_into(index, &mut pulled, used).map(|range| {
                        used = range.end;
                        TeamInput::Pulled(range)
                    })
                }
            };
            bytes = bytes.saturating_add(size);
            // (A member with bytes; `Nothing` was taken above.)
            let failed = input.is_err();
            inputs.push(input);
            index += 1;
            if failed {
                break;
            }
        }
        // A batch ends on a member it encodes: the empties after its last
        // one are left to the walk, which writes them either way.
        while matches!(inputs.last(), Some(Ok(TeamInput::Nothing))) {
            inputs.pop();
        }
        if !inputs.is_empty() {
            note_team_batch();
        }
        TeamBatch { inputs, pulled }
    }

    /// All of reader member `index`'s bytes, read into `buffer` from `at`,
    /// and the check that it has no more, as [`Run::pull_whole`] takes it:
    /// the same reads, into a batch's one buffer. Answers where they lie.
    pub(super) fn pull_into(
        &mut self,
        index: usize,
        buffer: &mut Vec<u8>,
        at: usize,
    ) -> Result<std::ops::Range<usize>> {
        let size = usize::try_from(self.members[index].size)
            .expect("a team member is at most the lane's reach");
        let end = at + size;
        // Grown, never cut back: the bytes below its length were touched
        // by an earlier batch and are read over as they are.
        if buffer.len() < end {
            buffer.resize(end, 0);
        }
        let bytes = &mut buffer[at..end];
        {
            let Run {
                members, prefix, ..
            } = self;
            let Payload::Reader { reader, .. } = &mut members[index].payload else {
                unreachable!("pull_into is asked only for a reader member")
            };
            // The head the samples held, then the reader
            // (`store::Prefix::read`), as every pull of a sampled member.
            let mut filled = 0;
            while filled < size {
                let read = prefix
                    .read(index, &mut **reader, &mut bytes[filled..])
                    .map_err(Error::from)?;
                if read == 0 {
                    return Err(Error::new(ErrorKind::Truncated));
                }
                filled += read;
            }
        }
        self.check_payload_end(index)?;
        Ok(at..end)
    }

    /// Keep a batch's buffer for the batch after next: two are in use
    /// where the next batch is planned ahead, and none is kept beyond
    /// them.
    pub(super) fn keep_pull(&mut self, buffer: Vec<u8>) {
        if !buffer.is_empty() && self.team_pulls.len() < 2 {
            self.team_pulls.push(buffer);
        }
    }

    /// All of reader member `index`'s bytes, and the check that it has no
    /// more ([`Run::check_payload_end`], taken HERE so the source can be
    /// closed now rather than held open until the member is written: a
    /// batch of several hundred open files would pass a process's file
    /// limit).
    ///
    /// The reads are the ones the windowed encode makes (spec G 3.7.2 and
    /// 3.7.3): a member of one window is asked for in reads of its whole
    /// length until it is filled, and a read of nothing before then is
    /// `Truncated`.
    pub(super) fn pull_whole(&mut self, index: usize) -> Result<Vec<u8>> {
        let size = usize::try_from(self.members[index].size)
            .expect("a team member is at most team_most bytes");
        // The kept buffer that fits most closely, or a new one of exactly
        // this size: a smaller one regrown freed its block every time.
        let fit = self
            .team_spare
            .iter()
            .enumerate()
            .filter(|(_, buffer)| buffer.capacity() >= size)
            .min_by_key(|(_, buffer)| buffer.capacity())
            .map(|(at, _)| at);
        let mut bytes = match fit {
            Some(at) => self.team_spare.swap_remove(at),
            None => Vec::with_capacity(size),
        };
        bytes.clear();
        bytes.resize(size, 0);
        let Payload::Reader { reader, .. } = &mut self.members[index].payload else {
            unreachable!("pull_whole is asked only for a reader member")
        };
        let mut filled = 0;
        while filled < size {
            let read = reader.read(&mut bytes[filled..]).map_err(Error::from)?;
            if read == 0 {
                return Err(Error::new(ErrorKind::Truncated));
            }
            filled += read;
        }
        self.check_payload_end(index)?;
        Ok(bytes)
    }

    /// Hands member `index` its packed bytes and unpacked digest from the
    /// team batch being written, or the error its pull ended in; `None`
    /// where the team did not encode it.
    pub(super) fn take_prepared(&mut self, index: usize) -> Option<Result<()>> {
        let at = index.checked_sub(self.team_from)?;
        let prepared = self.team_ready.get_mut(at)?.take()?;
        Some(prepared.map(|Prepared { packed, digest }| {
            // COPIED into `Run::packed`, not swapped, as the solid run's
            // batch does (`Run::take_ahead` there): `Run::packed` is also the
            // buffer a member above a window grows as the writing thread
            // encodes it, and swapped away it was freed and grown again by
            // doubling for the next one, every step a freed large block the
            // allocator kept resident (text4g at -m3: 115 MiB of RSS above
            // the live heap).
            // The lent buffer goes back to the pool.
            self.packed.clear();
            self.packed.extend_from_slice(&packed);
            self.pool_packed(packed);
            self.unpacked_digest = Some(digest);
            // A reader's end was checked when it was pulled.
            self.end_checked = Some(index);
            note_team_prepared();
        }))
    }

    /// Keep `buffer`, emptied, for the team to encode or pull into again
    /// (`Run::team_spare`), or drop it.
    ///
    /// A kept buffer keeps the capacity it last grew to, and that was
    /// TOUCHED, so it is resident and `Run::working_now` states it.
    /// Unbounded, the capacities drift up: a buffer that once held a large
    /// member keeps that size for every small one after it, and at -m5
    /// -mm256 tree5k's team held about 80 MiB of such buffers nobody
    /// stated. The kept buffers are held to [`TEAM_SPARE_BYTES`] between
    /// them, which is what two batches use, under a caller's ceiling and
    /// at the default policy alike.
    ///
    /// **At the default policy too since 28 Sep 2026.** The buffer a member
    /// written alone was packed into comes back here when the next team
    /// member is taken (`Run::take_prepared`), so a set of real binaries
    /// kept the packed capacity of every large member for the rest of the
    /// run: on the 4 GiB binary set (9,516 members, the largest 237 MB)
    /// the earlier code's stated peak read 645 to 844 MB and its whole process 565 to
    /// 684 MiB, over the 512 MiB ceiling, climbing steadily through the
    /// walk. Bounded, 189 to 196 MB stated and 309 to 336 MiB whole
    /// process, the same bytes and the same wall (counted untimed on an
    /// EPYC 9R45 at sixteen threads).
    pub(super) fn keep_spare(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();
        if self.team_spare.len() >= self.team_batch.0 {
            return;
        }
        if self
            .team_spare_bytes()
            .saturating_add(buffer.capacity() as u64)
            > self.team_spare_most()
        {
            return;
        }
        self.team_spare.push(buffer);
    }

    /// A buffer for a member of `size` unpacked bytes to be packed into:
    /// the pooled buffer that fits it most closely, or a new one, reserved
    /// to its packed bound either way, so the encoder never regrows it (a
    /// regrowth freed the old block, and macOS 27.0's allocator keeps a
    /// freed large block resident: bin4g at -m1 -s peaked at 664 MiB of
    /// RSS against 279 with its large-block cache off). One pool, shared
    /// by the solid batch and the worker team's crews.
    pub(super) fn lend_packed(&mut self, size: u64) -> Vec<u8> {
        let need = crate::encode::drive::packed_most(usize::try_from(size).unwrap_or(usize::MAX));
        let fit = self
            .packed_pool
            .iter()
            .enumerate()
            .filter(|(_, buffer)| buffer.capacity() >= need)
            .min_by_key(|(_, buffer)| buffer.capacity())
            .map(|(at, _)| at);
        match fit {
            Some(at) => self.packed_pool.swap_remove(at),
            None => {
                note_packed_fresh();
                Vec::with_capacity(need)
            }
        }
    }

    /// Keep a written member's packed buffer for [`Run::lend_packed`],
    /// emptied, while the pool holds less than `Run::packed_pool_most`.
    pub(super) fn pool_packed(&mut self, mut buffer: Vec<u8>) {
        let held: usize = self.packed_pool.iter().map(Vec::capacity).sum();
        if buffer.capacity() == 0 || held + buffer.capacity() > self.packed_pool_most() {
            self.packed_dropped = self.packed_dropped.saturating_add(buffer.capacity() as u64);
            return;
        }
        buffer.clear();
        self.packed_pool.push(buffer);
    }

    /// What the packed pool keeps between batches: [`PACKED_POOL_BYTES`],
    /// or twice a team batch's input where that is more, which the
    /// batch's packed bytes do not pass.
    pub(super) fn packed_pool_most(&self) -> usize {
        PACKED_POOL_BYTES
            .max(usize::try_from(self.team_batch.1.saturating_mul(2)).unwrap_or(usize::MAX))
    }

    /// The capacity the team's kept buffers hold between them.
    pub(super) fn team_spare_bytes(&self) -> u64 {
        self.team_spare
            .iter()
            .map(|buffer| buffer.capacity() as u64)
            .sum()
    }

    /// The walk with the worker team: every member in `add` order, as
    /// [`Run::walk`]'s member-at-a-time loop writes them, with the
    /// members the team takes ENCODED AHEAD by `width` crews.
    ///
    /// **Two batches are in flight, and a third's input.** While the crews
    /// encode one batch, this thread writes the batch before it, and any
    /// member between the two that the team does not take, through
    /// `Run::write_member` exactly as the member-at-a-time walk does; and
    /// then, where the working limit has room for one more batch's input,
    /// pulls the batch after (`Run::plan_ahead`), so the crews are not
    /// idle while it reads. The
    /// batch being written was encoded in the round before; each of its
    /// members finds its packed bytes waiting (`Run::take_prepared`) and
    /// is otherwise written as it always was: header, cipher, fragments,
    /// progress, in order.
    ///
    /// **Why the bytes are the member-at-a-time walk's.** A crew encodes a
    /// member with the same call the walk makes for it (`pack_member`), on
    /// an encoder built from the same figures (`Run::new_encoder`), and an
    /// encoder's output for a member never depends on the members it
    /// encoded before; the digest is the same function of the same bytes.
    /// Nothing else about a member is decided by the team: its cipher,
    /// its salt and its initialisation vector are drawn when it is
    /// WRITTEN, in `add` order, as before (spec G 3.13).
    ///
    /// **What it holds, stated in bytes.** Two batches' packed output, at
    /// most [`TEAM_BATCH_BYTES`] of input each plus a stored block's room
    /// apiece; the pulled bytes of the batch being encoded, when its
    /// members are readers; and `width` crews' encoders, each charged
    /// `Run::crew_bytes` by `Run::team_width` under a caller's ceiling.
    /// The crews' histories AND finders are counted in the round's high
    /// point, which is what `WriteReport::peak_working_memory` states.
    /// Nothing follows the archive.
    ///
    /// A reader is never pulled out of `add` order: a batch is not planned
    /// past a member that would pull one when written, until that member
    /// has been.
    pub(super) fn walk_team(&mut self, width: usize) -> Result<()> {
        let count = self.members.len();
        self.team_batch = self.team_batch(width);
        note_team_crews(width, self.team_most, self.large_crews, self.large_most);
        let rule = PackRule {
            window: self.window_bytes(),
            checksum: self.options.checksum,
            digest_threads: 1,
            depth: self.staged_depth(),
            slack: self.streamed_slack_multiple(),
        };
        self.team_charged = if self.large_crews > 0 {
            self.lane_charged
        } else if self.dial_ceiling().is_none() {
            (width as u64).saturating_mul(self.crew_charge())
        } else {
            0
        };
        // The next batch is planned AHEAD (`Run::plan_ahead`) only where
        // one more batch's input fits beside what the team and the run
        // are charged: the crews' widths are chosen without it, so at the
        // 512 MiB floor, where the charge is the room, the walk is the one
        // it was and no crew is given up for it (on eight threads there a
        // crew given up cost 4 percent of the wall of a 4 GiB set; counted
        // 1 Oct 2026 on the M5 Ultra).
        let ahead_room = self.dial_ceiling().is_none() && {
            let ceiling = team_ceiling(self.options.memory.working_limit);
            let charged = self
                .team_charged
                .saturating_add(self.beside_team_bytes(None));
            let batch = self
                .team_batch
                .1
                .saturating_add(self.large_largest.max(self.team_most));
            ceiling.saturating_sub(charged) >= batch
        };
        // The small crews and the large-member lane's (`Run::choose_large_lane`),
        // kept apart: a crew keeps the structures of the largest member it
        // has encoded.
        let mut crews: Vec<Encoder> = Vec::new();
        let mut large_crews: Vec<Encoder> = Vec::new();
        let large_width = self.large_crews.min(width);
        let small_width = width - large_width;
        let team_most = self.team_most;
        // Members `0..written` are out.
        let mut written = 0usize;
        // The batch the writing thread planned AHEAD, during the round
        // before, with where it starts (`Run::plan_ahead`).
        let mut ahead: Option<(usize, TeamBatch<'a>)> = None;
        loop {
            let (start, batch) = match ahead.take() {
                Some(planned) => planned,
                None => {
                    let tail = written.max(self.team_from + self.team_ready.len());
                    let start = (tail..count)
                        .find(|&index| self.team_takes(index))
                        .unwrap_or(count);
                    // Nor past a batch whose pull failed: the write ends at
                    // that member, and a member-at-a-time walk pulls nothing
                    // after it.
                    let blocked = (tail..start).any(|index| self.pulls(index))
                        || self
                            .team_ready
                            .iter()
                            .any(|prepared| matches!(prepared, Some(Err(_))));
                    let batch = if start < count && !blocked {
                        self.plan_batch(start)
                    } else {
                        TeamBatch {
                            inputs: Vec::new(),
                            pulled: Vec::new(),
                        }
                    };
                    (start, batch)
                }
            };
            let TeamBatch {
                inputs,
                pulled: batch_pulled,
            } = batch;
            // The batch's members in `add` order, the ones above
            // `Run::team_most` apart: only a large crew takes those.
            let length = |input: &Result<TeamInput<'a>>| match input {
                Ok(TeamInput::Slice(data)) => data.len() as u64,
                Ok(TeamInput::Pulled(range)) => range.len() as u64,
                Ok(TeamInput::Nothing) | Err(_) => 0,
            };
            let (big, small): (Vec<usize>, Vec<usize>) = (0..inputs.len())
                .filter(|&index| !matches!(inputs[index], Ok(TeamInput::Nothing)))
                .partition(|&index| length(&inputs[index]) > team_most);
            let large_count = large_width.min(inputs.len());
            let small_count = small_width.min(small.len());
            while crews.len() < small_count {
                crews.push(self.new_encoder());
            }
            while large_crews.len() < large_count {
                large_crews.push(self.encoder_held(Some(LARGE_CREW_HOLD)));
            }
            let slots: Vec<OnceLock<Prepared>> = inputs.iter().map(|_| OnceLock::new()).collect();
            let next_small = AtomicUsize::new(0);
            let next_big = AtomicUsize::new(0);
            let roles = AtomicUsize::new(0);
            // What the pool does not keep of the batch this round writes
            // is counted from here (`Run::pool_packed`).
            self.packed_dropped = 0;
            // Each member is lent its packed buffer here, on the writing
            // thread, before the crews start (`Run::lend_packed`).
            let lent: Vec<Mutex<Vec<u8>>> = inputs
                .iter()
                .map(|input| {
                    let size = length(input);
                    Mutex::new(if size > 0 {
                        self.lend_packed(size)
                    } else {
                        Vec::new()
                    })
                })
                .collect();
            let idle = Mutex::new(std::mem::take(&mut crews));
            let idle_large = Mutex::new(std::mem::take(&mut large_crews));
            let pack = |encoder: &mut Encoder, index: usize| {
                if let Ok(input) = &inputs[index] {
                    let buffer = std::mem::take(&mut *lock(&lent[index]));
                    let prepared = pack_member(encoder, input, &batch_pulled, rule, buffer);
                    assert!(slots[index].set(prepared).is_ok(), "one crew per member");
                }
            };
            let crew = || {
                // The first `large_count` crews spawned are the large ones:
                // the batch's large members, then its small ones.
                let large = roles.fetch_add(1, Ordering::Relaxed) < large_count;
                let pool = if large { &idle_large } else { &idle };
                let Some(mut encoder) = lock(pool).pop() else {
                    return;
                };
                if large {
                    while let Some(&index) = big.get(next_big.fetch_add(1, Ordering::Relaxed)) {
                        pack(&mut encoder, index);
                    }
                }
                while let Some(&index) = small.get(next_small.fetch_add(1, Ordering::Relaxed)) {
                    pack(&mut encoder, index);
                }
                lock(pool).push(encoder);
            };
            // The next batch is planned inside this round, once this
            // thread has written what the round writes, where it would be
            // planned at the top of the next one: this batch pulled whole
            // (an error ends the write at its member), and room for one
            // more batch's input (`ahead_room`; never under a ceiling).
            let pulled_whole = !inputs.is_empty() && inputs.iter().all(Result::is_ok);
            let ahead_from = (pulled_whole && ahead_room).then_some(start + inputs.len());
            let outcome =
                self.team_round(written..start, large_count + small_count, &crew, ahead_from);
            // Every crew has finished: the scope in `team_round` waits for
            // them whether the writing thread succeeded or not.
            crews = idle.into_inner().unwrap_or_else(|e| e.into_inner());
            large_crews = idle_large.into_inner().unwrap_or_else(|e| e.into_inner());
            ahead = outcome?;

            // The round's high point: the batch just encoded, whole, and
            // everything the team held beside it at any instant of the
            // round - the batch written in it and the pulled input -
            // counted together, which is an upper bound and never under,
            // and each buffer ONCE. The batch written in the round: its
            // packed buffers went back to the pool as they were written
            // (`Run::take_prepared`), where `Run::team_now` counts them,
            // so only the ones the pool did not keep are added here. This
            // batch's pulled buffer and the buffer of the batch planned
            // ahead, each at the length it has ever been touched to; this
            // batch's is kept for the next (`Run::keep_pull`) only AFTER
            // the sample, or the kept buffers would state it again. (Until
            // 1 Oct 2026 both were stated twice, which a batch of 16 MiB
            // hid and the lane's reach did not: bin4g at -m3 under a 2 GiB
            // budget stated 2,191 MiB against a limit of 1,991 while it
            // held 1,820.)
            let pulled = (batch_pulled.len() as u64).saturating_add(
                ahead
                    .as_ref()
                    .map_or(0, |(_, planned)| planned.pulled.len() as u64),
            );
            // A crew's finder is part of what it holds: at the default
            // policy the width is not bounded by it (`Run::team_width`),
            // so the report is where it is stated.
            let crew_held: u64 = crews
                .iter()
                .chain(&large_crews)
                .map(|crew| {
                    crew.held_bytes()
                        .saturating_add(crew.structure_bytes())
                        .saturating_add(crew.flight_bytes())
                })
                .sum();
            self.team_from = start;
            self.team_ready = inputs
                .into_iter()
                .zip(slots)
                .map(|(input, slot)| {
                    // A member the batch passed over is the writing
                    // thread's (`Run::take_prepared` finds nothing).
                    if matches!(input, Ok(TeamInput::Nothing)) {
                        return None;
                    }
                    Some(match input {
                        Ok(_) => Ok(slot.into_inner().expect("every member was encoded")),
                        Err(error) => Err(error),
                    })
                })
                .collect();
            self.team_resident = crew_held;
            self.team_held = self.packed_dropped.saturating_add(pulled);
            self.note_peak();
            self.team_held = 0;
            self.keep_pull(batch_pulled);
            written = start;
            if written >= count && self.team_ready.is_empty() && ahead.is_none() {
                self.team_resident = 0;
                self.team_charged = 0;
                return Ok(());
            }
        }
    }

    /// One round of [`Run::walk_team`]: `crews` crews run `crew` on the
    /// pool while this thread writes the members of `write`, and the
    /// round ends when both have. The writing is never moved off this
    /// thread, which is what lets the output, the payloads and the
    /// progress observer stay the caller's and need not be `Send`.
    ///
    /// With `ahead_from`, the end of the batch the crews are encoding,
    /// this thread then plans the NEXT batch (`Run::plan_ahead`) while the
    /// crews still run, and answers it.
    pub(super) fn team_round(
        &mut self,
        write: std::ops::Range<usize>,
        crews: usize,
        crew: &(dyn Fn() + Sync),
        ahead_from: Option<usize>,
    ) -> Result<Option<(usize, TeamBatch<'a>)>> {
        #[cfg(feature = "parallel")]
        {
            width::scope_here(|scope| {
                for _ in 0..crews {
                    scope.spawn(move |_| crew());
                }
                for index in write {
                    self.write_member(index)?;
                }
                Ok(ahead_from.and_then(|tail| self.plan_ahead(tail)))
            })
        }
        #[cfg(not(feature = "parallel"))]
        {
            // `team_width` is one without the pool, so no round is ever
            // run here; the arm keeps the walk whole in either build.
            for _ in 0..crews {
                crew();
            }
            for index in write {
                self.write_member(index)?;
            }
            Ok(ahead_from.and_then(|tail| self.plan_ahead(tail)))
        }
    }

    /// The batch after the one being encoded, which ends at `tail`,
    /// planned by the writing thread WHILE the crews encode: where it
    /// starts and its inputs, or nothing where the walk would not plan it
    /// yet.
    ///
    /// **Why.** A batch's readers are pulled, and the store rule's samples
    /// judged, by this thread and in `add` order, and between rounds that
    /// was this thread working alone with every crew idle: counted 1 Oct
    /// 2026 on the 4 GiB set of real binaries at level 1 and 16 threads
    /// (a Zen 4 rental), 43 percent of the wall had one thread running.
    ///
    /// **Why it is the same walk.** It is `Run::plan_batch` from the member
    /// the next round's own plan would start at, under the rule that plan
    /// obeys: nothing is planned past a member that pulls a reader when
    /// it is written (so readers are still pulled in `add` order, and the
    /// one member whose sampled head the store rule holds, `store::Prefix`,
    /// is still the next reader written), and the
    /// caller plans nothing ahead of a batch whose pull failed. Every
    /// member before `tail` that this thread writes itself has been
    /// written when this is called.
    ///
    /// **What it holds.** One more batch's pulled input than the walk
    /// without it, so the caller plans ahead only where that much room is
    /// left beside the team's charge (`Run::walk_team`), and never under a
    /// caller's ceiling; it is in the round's stated high point.
    pub(super) fn plan_ahead(&mut self, tail: usize) -> Option<(usize, TeamBatch<'a>)> {
        let count = self.members.len();
        let start = (tail..count)
            .find(|&index| self.team_takes(index))
            .unwrap_or(count);
        if start >= count || (tail..start).any(|index| self.pulls(index)) {
            return None;
        }
        let batch = self.plan_batch(start);
        if batch.inputs.is_empty() {
            self.keep_pull(batch.pulled);
            return None;
        }
        Some((start, batch))
    }
}
