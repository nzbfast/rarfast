//! The solid path: a run of members staged as one batch and encoded as
//! one wave, with the next batch's readers pulled beside the flush.

use super::*;

/// Whether a SOLID set takes the default lazy parse over the tree at
/// levels 4 and 5. It does since 30 Sep 2026 (on
/// SPEC-H3 8.1's pending solid question): a solid set takes the plan like
/// any member that is not lone, and `WriteOptions::level4_optimal` and
/// `level5_optimal` keep the optimal parse over the tree there as
/// everywhere. `false` gives back the rule before that date, a solid
/// set keeping the optimal parse whatever the options say; this is the
/// one site that reads it (`Run::encoder_capped`).
pub(super) const SOLID_TAKES_LAZY_TREE: bool = true;

// The pipelining DEPTH this thread writes at: the most members one batch
// stages and parses as a single wave.
//
// It exists so that the claim the depth rests on can be CHECKED rather
// than asserted. A batch is a wave's width and never a member's bytes, so
// a solid set written at any depth is the same archive, and
// `tests/solid_volume_pipeline.rs` writes each shape at depth 1 - which is
// a member at a time, the walk this engine had before a batch existed -
// and at 2, 4 and 32, and compares the bytes. Nothing outside this
// repository's own tests can reach it, and nothing in a shipped build
// carries it: without `bench-internals` the depth is the constant.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static BATCH_DEPTH: std::cell::Cell<usize> =
        const { std::cell::Cell::new(crate::encode::drive::BATCH_MEMBERS_MOST) };
}

/// The pool's scope as the writing thread sees it while a flush runs
/// beside it ([`beside_with`]): somewhere to hand a task to.
pub(super) struct Tasks<'a, 'scope> {
    #[cfg(feature = "parallel")]
    pub(super) scope: &'a rayon::Scope<'scope>,
    #[cfg(not(feature = "parallel"))]
    pub(super) scope: std::marker::PhantomData<&'a &'scope ()>,
}

impl<'scope> Tasks<'_, 'scope> {
    /// Hand `task` to the pool; without the pool it runs here.
    pub(super) fn spawn(&self, task: impl FnOnce() + Send + 'scope) {
        #[cfg(feature = "parallel")]
        self.scope.spawn(move |_| task());
        #[cfg(not(feature = "parallel"))]
        {
            let _ = self.scope;
            task();
        }
    }
}

/// Run `pool` on the pool and `here` on this thread at the same time, and
/// return when both have: the writing thread pulls the next batch's
/// readers while the pool encodes this one (`Run::batch_solid`), and a
/// reader is still pulled by the writing thread alone. `here` is handed
/// the pool's scope, so that the writing thread can give the pool tasks of
/// its own while the flush runs; they are waited for too.
pub(super) fn beside_with<'scope, A, B>(pool: A, here: B)
where
    A: FnOnce() + Send + 'scope,
    B: FnOnce(&Tasks<'_, 'scope>),
{
    #[cfg(feature = "parallel")]
    width::scope_here(|scope| {
        scope.spawn(move |_| pool());
        here(&Tasks { scope });
    });
    #[cfg(not(feature = "parallel"))]
    {
        pool();
        here(&Tasks {
            scope: std::marker::PhantomData,
        });
    }
}

/// All of a reader member's bytes, into `bytes`, which is as long as the
/// member, and the check that it has no more: `Run::pull_whole`'s reads
/// and `Run::check_payload_end`'s check, on a member alone, so it can run
/// beside the encoder.
pub(super) fn pull_into(member: &mut Planned<'_>, bytes: &mut [u8]) -> Result<()> {
    let size = bytes.len();
    let name = member.name;
    let Payload::Reader { reader, .. } = &mut member.payload else {
        unreachable!("pull_into is asked only for a reader member")
    };
    let mut filled = 0;
    while filled < size {
        let read = reader.read(&mut bytes[filled..]).map_err(Error::from)?;
        if read == 0 {
            return Err(Error::new(ErrorKind::Truncated));
        }
        filled += read;
    }
    let mut over = [0u8; 1];
    match reader.read(&mut over) {
        Ok(0) => Ok(()),
        Ok(_) => Err(Error::new(ErrorKind::Corrupt(Corruption::PayloadLength)).with_member(name)),
        Err(error) => Err(Error::from(error)),
    }
}

/// Where a member pulled ahead lies in `Run::prefetch_buf`, and its
/// unpacked digest.
pub(super) type Pulled = (std::ops::Range<usize>, Digest);

/// What the writing thread pulls beside a flush for the members after it
/// (`Run::ahead_plan`): the next batch's readers, each with whether spec G
/// 3.8.3 samples it, and a reader longer than a window whose head is
/// sampled.
#[derive(Default)]
pub(super) struct Ahead {
    pub(super) pulls: Vec<(usize, bool)>,
    pub(super) head: Option<usize>,
    /// `WriteOptions::store_one_miss`, for the misses each vote allows.
    pub(super) one_miss: bool,
}

impl Ahead {
    pub(super) fn is_empty(&self) -> bool {
        self.pulls.is_empty() && self.head.is_none()
    }
}

/// One verdict due beside a flush.
pub(super) enum Vote<'d> {
    /// Member `at`, pulled whole: its bytes and the misses it is allowed.
    Member {
        at: usize,
        span: &'d [u8],
        most_misses: usize,
    },
    /// The leading samples of a head, end to end
    /// (`store::Prefix::pull_leading`).
    Head { samples: Vec<u8>, sample: usize },
}

/// The verdicts spec G 3.8.3 owes the members pulled beside a flush, and
/// who takes them: WHOEVER IS FREE.
///
/// The writing thread posts a vote as it pulls each member and hands the
/// pool a task that takes posted votes; when it has pulled everything it
/// takes what is left itself. So on a wide pool, which at the low levels
/// is mostly idle while the writing thread is the one thing every byte
/// passes through, the samples are packed on pool threads and cost the
/// writing thread nothing; and on a pool of one thread, which is busy
/// with the flush, the writing thread packs them while it would only have
/// waited.
///
/// Both other shapes were counted on bin4g (9,516 members, 413 of them of
/// 1 MiB and more, about 960 samples of 1.4 ms) and lost: verdicts the
/// writing thread asked the pool for and WAITED on, one member after
/// another, were 1.7 s of wall in 22 at -m1 -s on Zen 4 rental A; and
/// verdicts the writing thread always took itself were level there but
/// 0.3 s in 7.5 on Zen 4 rental B, whose flushes are shorter than the
/// samples.
pub(super) struct Votes<'d> {
    pub(super) judges: &'d store::Judges,
    pub(super) posted: Mutex<Vec<Vote<'d>>>,
    /// Each member's verdict: whether it is written stored.
    pub(super) members: Mutex<Vec<(usize, bool)>>,
    /// How many of the head's leading samples compress.
    pub(super) head: Mutex<Option<usize>>,
}

impl<'d> Votes<'d> {
    pub(super) fn new(judges: &'d store::Judges) -> Votes<'d> {
        Votes {
            judges,
            posted: Mutex::new(Vec::new()),
            members: Mutex::new(Vec::new()),
            head: Mutex::new(None),
        }
    }

    /// Post `vote` and hand the pool a task that takes posted votes.
    pub(super) fn post<'v>(&'v self, vote: Vote<'d>, tasks: &Tasks<'_, 'v>) {
        lock(&self.posted).push(vote);
        tasks.spawn(move || self.take());
    }

    /// Take posted votes until none is left.
    pub(super) fn take(&self) {
        loop {
            let Some(vote) = lock(&self.posted).pop() else {
                return;
            };
            match vote {
                Vote::Member {
                    at,
                    span,
                    most_misses,
                } => {
                    let stores = self.judges.say_store(span, most_misses);
                    lock(&self.members).push((at, stores));
                }
                Vote::Head { samples, sample } => {
                    let misses = self.judges.misses_in(&samples, sample);
                    *lock(&self.head) = Some(misses);
                }
            }
        }
    }
}

/// What [`pull_ahead`] pulled.
#[derive(Default)]
pub(super) struct AheadPulled {
    /// How much of `Run::prefetch_buf` holds pulled members: less than it
    /// was sized to where a pull failed.
    pub(super) filled: usize,
    /// The head pulled for the plan's long member, as far as its leading
    /// samples, or the error its pull ended in.
    pub(super) head: Option<(usize, Result<Prefix>)>,
}

/// What a flush with [`pull_ahead`] beside it leaves for the run to keep
/// ([`flush_beside`], `Run::keep_ahead`).
pub(super) struct AheadKept {
    pub(super) pulled: AheadPulled,
    /// Each judged member's verdict: whether it is written stored.
    pub(super) verdicts: Vec<(usize, bool)>,
    /// How many of the head's leading samples compress.
    pub(super) head_misses: Option<usize>,
}

/// Run `flush` on the pool with [`pull_ahead`] of `plan` beside it on this
/// thread, and answer what was pulled and judged once both have ended.
pub(super) fn flush_beside(
    flush: impl FnOnce() + Send,
    plan: Ahead,
    members: &mut [Planned<'_>],
    prefetched: &mut std::collections::VecDeque<(usize, Result<Pulled>)>,
    prefetch_buf: &mut Vec<u8>,
    judges: &store::Judges,
    checksum: ChecksumKind,
) -> AheadKept {
    // The plan has pulls only while nothing waits in the buffer, so a
    // round that pulls starts it afresh, sized for every member the round
    // pulls: a stretch of it is judged while the next is pulled into.
    let pulls = !plan.pulls.is_empty();
    if pulls {
        debug_assert!(prefetched.is_empty());
        let total: u64 = plan.pulls.iter().map(|(at, _)| members[*at].size).sum();
        prefetch_buf.clear();
        prefetch_buf.resize(usize::try_from(total).expect("a batch's input"), 0);
    }
    let votes = Votes::new(judges);
    let mut pulled = AheadPulled::default();
    {
        let buf: &mut [u8] = if pulls {
            &mut prefetch_buf[..]
        } else {
            &mut []
        };
        let (votes, pulled) = (&votes, &mut pulled);
        beside_with(flush, move |tasks| {
            *pulled = pull_ahead(plan, members, prefetched, buf, votes, tasks, checksum);
        });
    }
    let verdicts = std::mem::take(&mut *lock(&votes.members));
    let head_misses = lock(&votes.head).take();
    drop(votes);
    if pulls {
        prefetch_buf.truncate(pulled.filled);
    }
    AheadKept {
        pulled,
        verdicts,
        head_misses,
    }
}

/// Pull what `plan` names, on the WRITING thread, while the pool parses
/// beside it ([`beside_with`]), and post the verdicts spec G 3.8.3 owes it
/// ([`Votes`]).
///
/// The pulls are the ones the batch after would have made: each reader
/// whole, in `add` order, into its own stretch of `buf` (which the caller
/// sized for them all, so that a stretch can be judged while the next is
/// pulled), hashed as it is pulled. The head of `plan.head` is pulled as
/// far as the leading samples of its vote, which is as far as a member
/// that compresses is ever pulled, and those samples are posted; a head
/// they do not settle is finished when the writer reaches its member
/// (`store::Prefix::finish_wide`).
#[allow(clippy::too_many_arguments)]
pub(super) fn pull_ahead<'d, 'v>(
    plan: Ahead,
    members: &mut [Planned<'_>],
    prefetched: &mut std::collections::VecDeque<(usize, Result<Pulled>)>,
    buf: &'d mut [u8],
    votes: &'v Votes<'d>,
    tasks: &Tasks<'_, 'v>,
    checksum: ChecksumKind,
) -> AheadPulled {
    let mut out = AheadPulled::default();
    let mut rest = buf;
    let mut failed = false;
    for (at, judges_it) in plan.pulls {
        let size = usize::try_from(members[at].size).expect("a batched member is at most a window");
        let (mine, after) = std::mem::take(&mut rest).split_at_mut(size);
        rest = after;
        let pulled = pull_into(&mut members[at], mine).map(|()| {
            // Hashed while the pool encodes beside this thread, so the
            // digest hashes on this thread alone
            // (`Run::digest_threads`).
            let mut digest = new_running(checksum, 1);
            digest.update(mine);
            (out.filled..out.filled + size, digest.finish())
        });
        failed = pulled.is_err();
        prefetched.push_back((at, pulled));
        if failed {
            break;
        }
        out.filled += size;
        if judges_it {
            let most_misses = store::most_misses(members[at].size, plan.one_miss);
            let span: &'d [u8] = mine;
            votes.post(
                Vote::Member {
                    at,
                    span,
                    most_misses,
                },
                tasks,
            );
        }
    }
    if let (Some(at), false) = (plan.head, failed) {
        let span = usize::try_from(members[at].size.min(store::PREFIX_BYTES as u64))
            .expect("the prefix is at most 32 MiB");
        let most_misses = store::most_misses(members[at].size, plan.one_miss);
        let Payload::Reader { reader, .. } = &mut members[at].payload else {
            unreachable!("a head is planned only for a reader member")
        };
        let mut head = Prefix::default();
        let pulled = head.pull_leading(at, &mut **reader, span, most_misses);
        out.head = Some((
            at,
            pulled.map(|samples| {
                let sample = store::SAMPLE_BYTES.min(span);
                votes.post(Vote::Head { samples, sample }, tasks);
                head
            }),
        ));
    }
    // What no pool thread has taken yet is this thread's.
    votes.take();
    out
}

/// The most members one batch stages (see the comment above).
pub(super) fn batch_depth() -> usize {
    #[cfg(feature = "bench-internals")]
    {
        BATCH_DEPTH.with(std::cell::Cell::get).max(1)
    }
    #[cfg(not(feature = "bench-internals"))]
    {
        crate::encode::drive::BATCH_MEMBERS_MOST
    }
}

/// Runs `work` with this thread's pipelining depth set to `depth`, and
/// puts it back afterwards. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_batch_depth<T>(depth: usize, work: impl FnOnce() -> T) -> T {
    let was = BATCH_DEPTH.with(std::cell::Cell::get);
    BATCH_DEPTH.with(|cell| cell.set(depth));
    let answer = work();
    BATCH_DEPTH.with(|cell| cell.set(was));
    answer
}

/// What a batch allows per member for the member's own HEADER when it
/// bounds itself by the volume's remaining room (`Run::batch_solid`).
///
/// It is an allowance and not a measurement: the room it guards is
/// already an over-estimate, and the only thing an under-estimate costs
/// is one discarded tail at the boundary. A RAR 5 file header of a member
/// with a 255 byte name fits inside it.
pub(super) const BATCH_HEADER_ROOM: u64 = 320;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// Keep what a flush pulled and judged beside itself ([`flush_beside`]):
    /// each judged member's verdict, and the long member's head with how
    /// many of its leading samples compress, which is its verdict where
    /// they are more than its vote allows; a head they do not settle is
    /// finished when the writer reaches the member (`Run::sample_member`).
    pub(super) fn keep_ahead(&mut self, kept: AheadKept) {
        for (at, stores) in kept.verdicts {
            self.sampled[at] = true;
            self.stored_by_sample[at] = stores;
        }
        match kept.pulled.head {
            Some((at, Ok(head))) => {
                let misses = kept
                    .head_misses
                    .expect("a head's vote is taken beside the flush that pulled it");
                if misses > self.options.store_misses(self.members[at].size) {
                    self.sampled[at] = true;
                }
                self.head_ahead = Some((at, head, misses));
            }
            Some((at, Err(error))) => self.head_failed = Some((at, error)),
            None => {}
        }
        self.note_peak();
    }

    /// Take member `index`, which a solid batch pulled ahead and the
    /// samples STORE, out of the pulls waiting (`Run::prefetched`) and
    /// hold its bytes for the stored path (`store::Prefix::hold`), as the
    /// writer reaches it. Nothing where it is not waiting there.
    pub(super) fn claim_prefetched(&mut self, index: usize) {
        if !self.stored_by_sample[index]
            || self.prefetched.front().is_none_or(|(at, _)| *at != index)
        {
            return;
        }
        if let Some((_, Ok((range, _)))) = self.prefetched.pop_front() {
            self.prefix.hold(index, self.prefetch_buf[range].to_vec());
        }
        if self.prefetched.is_empty() {
            self.prefetch_buf.clear();
        }
        self.note_peak();
    }

    /// Whether member `index` may be encoded as part of a BATCH.
    ///
    /// A batch is a run of members staged together and parsed as one
    /// wave, which is what keeps the parse wide across a solid set's
    /// member boundaries (measured: a 512 KiB solid member
    /// is two parse blocks, and a wave that ends where the member does
    /// ran 1.90x parallel where the same bytes in one member ran 10.63x).
    /// What it costs is that the packed output of a member the writer has
    /// not reached yet is held, so the batch is bounded.
    ///
    /// The conditions are each a thing that would otherwise make the
    /// batch WRONG rather than merely slow:
    ///
    /// - SOLID, because a batch is one carried run and nothing else
    ///   carries;
    /// - bytes in memory, or a READER, which the batch pulls WHOLE, in
    ///   `add` order, by this thread, taking its unpacked checksum and
    ///   checking its end as it goes ([`Run::pull_whole`], as the worker
    ///   team pulls one), because a batch pulls several members' input
    ///   before writing any of them. In a VOLUME SET too, since 1 Oct
    ///   2026, where a reader was left to the member-at-a-time walk
    ///   before: 5,000 members of a solid set were 5,000 waves of a block
    ///   or two, at 3.9x to 6.5x the wall of the same set in one archive at
    ///   levels 3 and 5.
    ///   The two things that kept it out are answered: a batch whose tail
    ///   lands past a boundary is DISCARDED and encoded again (below), and
    ///   a reader cannot be pulled twice, so a volume set KEEPS the bytes
    ///   a batch pulled until the batch after is staged
    ///   (`Run::ahead_input`, `Run::restage`); and a caller that reported
    ///   volume boundaries against the member it last pulled (the command
    ///   line's progress lines did) is told which member the writer has
    ///   taken up (`Progress::member_started`, `Run::announce`). Not under
    ///   a ceiling the caller NAMED below the default policy's floor
    ///   (`Run::small_ceiling`), where the named path is the one it was
    ///   and a volume set's readers keep the member-at-a-time walk and its
    ///   peak: counted on 5,000 files at `-m5 -s -v4m -mm96m`, batched,
    ///   the run stated 147 MiB where a member at a time stated 61, and a
    ///   budget the user set is hard. At 512 MiB and above the
    ///   batch is far inside it (59 MiB stated at `-m3`, 147 at `-m5`);
    /// - one WINDOW at most, because a member longer than that is handed
    ///   over in several chunks and is already wide enough to fill a wave
    ///   on its own;
    /// - compressed and not empty, because nothing else reaches the
    ///   encoder at all: not a member spec G 3.8.3's samples are already
    ///   known to STORE, which ends a batch before itself.
    ///
    /// **A VOLUME SET batches too, and this is what makes that sound.** A
    /// volume boundary ENDS a solid run (spec G 3.9), and where it falls
    /// is not known until the packed bytes before it are written, so a
    /// batch may turn out to span one. What makes that harmless is that a
    /// batch moves no byte of any member's packed output: every block is
    /// parsed from its own member's bytes over the history in front of
    /// it, which is the property `Engine::flush` rests on to widen the
    /// wave at all. A batch whose tail lands the far side of a boundary
    /// is therefore DISCARDED there (`Run::next_volume`) and encoded
    /// again from the reset run, and the set's bytes are the same as they
    /// would be a member at a time. `Run::batch_solid` keeps that discard
    /// rare by not staging past the volume's remaining room.
    pub(super) fn may_batch(&self, index: usize) -> bool {
        self.options.solid
            && !self.options.stored()
            && !self.stored_by_sample[index]
            && !self.members[index].is_directory
            && self.members[index].size > 0
            && self.members[index].size <= self.window_bytes() as u64
            && match self.members[index].payload {
                Payload::Bytes(_) => true,
                Payload::Reader { .. } => {
                    !self.options.volume_set() || self.small_ceiling().is_none()
                }
            }
    }

    /// Copy the packed bytes member `index` already has from a batch into
    /// [`Run::packed`], answering whether it had any; the batch's buffer
    /// goes back to the pool it was lent from ([`Run::lend_packed`]).
    ///
    /// COPIED, not swapped. [`Run::packed`] is also the buffer a member
    /// longer than a window grows as its windows are encoded
    /// (`Run::compress_streaming`), and it keeps that capacity for the
    /// next such member, as a member-at-a-time walk does. Swapped away, it
    /// went to the pool, which a buffer of 100 MiB does not fit, and was
    /// freed, and the next long member grew a new one by doubling from
    /// nothing, freeing every step: on bin4g at -m1 -s the heap counted
    /// hundreds of MiB freed in every class from 2 to 128 MiB, which
    /// macOS 27.0's allocator kept resident (781 MiB of RSS against
    /// the earlier code's 218). A batch member's packed bytes are at most one window,
    /// and one copy of them is cheap beside their encode.
    pub(super) fn take_ahead(&mut self, index: usize) -> bool {
        let Some(at) = index.checked_sub(self.ahead_from) else {
            return false;
        };
        if at >= self.ahead_len {
            return false;
        }
        self.packed.clear();
        self.packed.extend_from_slice(&self.ahead[at]);
        // A reader's digest was taken, and its end checked, as it was
        // pulled.
        if let Some(digest) = self.ahead_digests[at] {
            self.unpacked_digest = Some(digest);
            self.end_checked = Some(index);
        }
        // Left full, the slot would be counted as held alongside this
        // member by `Run::working_now`, which would report a peak the run
        // never reached; and a slot that kept its buffer kept the capacity
        // of the largest member it ever held, hundreds of MiB across 1,024
        // slots on bin4g's real binaries. It goes back to the pool and the
        // slot is left empty.
        let spent = std::mem::take(&mut self.ahead[at]);
        self.pool_packed(spent);
        true
    }

    /// Keep the bytes of the batch's READER members the writer has not
    /// reached, as a volume boundary discards the batch
    /// ([`Run::next_volume`]): they are staged again from `restage` by the
    /// batch after ([`Run::batch_solid`]), since a reader is pulled once.
    /// A member whose packed bytes the writer has taken
    /// ([`Run::take_ahead`] leaves its slot empty) is written, or being
    /// written, and is not kept. Readers an earlier boundary left waiting
    /// follow the batch's, as their members do.
    pub(super) fn keep_unwritten(&mut self) {
        if self.ahead_kept.is_empty() {
            return;
        }
        let mut bytes = Vec::new();
        let mut waiting = std::collections::VecDeque::new();
        for (member, (range, digest)) in self.ahead_kept.drain(..) {
            let unwritten = member
                .checked_sub(self.ahead_from)
                .is_some_and(|at| at < self.ahead_len && !self.ahead[at].is_empty());
            if unwritten {
                let start = bytes.len();
                bytes.extend_from_slice(&self.ahead_input[range]);
                waiting.push_back((member, (start..bytes.len(), digest)));
            }
        }
        for (member, (range, digest)) in self.restage.drain(..) {
            let start = bytes.len();
            bytes.extend_from_slice(&self.restage_buf[range]);
            waiting.push_back((member, (start..bytes.len(), digest)));
        }
        self.ahead_input.clear();
        self.restage_buf = bytes;
        self.restage = waiting;
        self.note_peak();
    }

    /// The error member `index`'s reader failed with when a batch pulled
    /// it ([`Run::batch_solid`]), taken, or `None`.
    pub(super) fn take_pull_failed(&mut self, index: usize) -> Option<Error> {
        match &self.pull_failed {
            Some((at, _)) if *at == index => self.pull_failed.take().map(|(_, error)| error),
            _ => None,
        }
    }

    /// The reader members the batch after one ending before `from` will
    /// pull, which `Run::batch_solid` pulls while that batch is encoded:
    /// the batchable readers from `from` on, as many as a batch holds,
    /// passing over members that pull nothing (a directory, an empty
    /// member, bytes in memory) and stopping at a reader any other path
    /// would pull, so every reader is still pulled once, whole, in `add`
    /// order, by the writing thread. None under a caller's ceiling, whose
    /// charges do not count a second batch's input.
    ///
    /// With them, which of them spec G 3.8.3 samples, and the reader the
    /// list stopped at where that is one LONGER than a window the rule
    /// samples, whose head the writing thread pulls and judges beside the
    /// same flush (`pull_ahead`): every reader before it has been pulled
    /// by then, so it is still pulled in `add` order. Not in a volume set,
    /// where a reader longer than a window is the streamed walk's and its
    /// vote stays with the caller (`Run::sample_solid`).
    pub(super) fn ahead_plan(&self, from: usize) -> Ahead {
        let (list, stopped) = self.prefetch_list(from);
        let head = stopped.filter(|&at| {
            self.head_ahead.is_none()
                && self.head_failed.is_none()
                && !self.options.volume_set()
                && self.may_sample(at)
                && !self.sampled[at]
                && self.members[at].size > self.window_bytes() as u64
                && matches!(self.members[at].payload, Payload::Reader { .. })
        });
        Ahead {
            pulls: list
                .into_iter()
                .map(|at| (at, self.may_sample(at) && !self.sampled[at]))
                .collect(),
            head,
            one_miss: self.options.store_one_miss,
        }
    }

    /// The readers of [`Run::ahead_plan`], and the reader the list stopped
    /// at when it stopped at one no batch takes.
    pub(super) fn prefetch_list(&self, from: usize) -> (Vec<usize>, Option<usize>) {
        let mut list = Vec::new();
        if self.dial_ceiling().is_some() {
            return (list, None);
        }
        // The next batch's input and no more: a solid batch is held to
        // its slack, eight MiB at the default dictionary, whatever the
        // batch's block count allows.
        let dictionary = usize::try_from(self.dictionary).unwrap_or(usize::MAX);
        let most = crate::encode::drive::Engine::solid_batch_bytes(dictionary) as u64;
        let mut bytes = 0u64;
        for at in from..self.members.len() {
            if list.len() >= batch_depth() {
                break;
            }
            let member = &self.members[at];
            if member.is_directory
                || member.size == 0
                || matches!(member.payload, Payload::Bytes(_))
            {
                continue;
            }
            if !self.may_batch(at) {
                return (list, Some(at));
            }
            if !list.is_empty() && bytes + member.size > most {
                break;
            }
            bytes += member.size;
            list.push(at);
        }
        (list, None)
    }

    /// The room a batch aims to stay inside, in packed bytes.
    ///
    /// It is the volume's remaining budget less a margin, because a batch
    /// that aims exactly at the boundary straddles it as often as not and
    /// a batch that stops just short of it does not. Outside a volume set
    /// the budget is `u64::MAX` and this bounds nothing.
    pub(super) fn batch_room(&self) -> u64 {
        if self.budget == u64::MAX {
            return u64::MAX;
        }
        self.budget / 10 * 9
    }

    /// What a member of `size` unpacked bytes is expected to cost the
    /// volume: its packed bytes at the ratio this run has seen so far,
    /// and a header (`Run::packed_seen`).
    ///
    /// Before any compressed member has been written the run knows
    /// nothing, and the estimate is the unpacked size itself, which is
    /// the conservative answer.
    pub(super) fn packed_estimate(&self, size: u64) -> u64 {
        let packed = if self.unpacked_seen == 0 {
            size
        } else {
            let scaled =
                u128::from(size) * u128::from(self.packed_seen) / u128::from(self.unpacked_seen);
            u64::try_from(scaled).unwrap_or(u64::MAX)
        };
        packed.saturating_add(BATCH_HEADER_ROOM)
    }

    /// Stage the run of batchable members starting at `index` and encode
    /// them as ONE wave, keeping their packed bytes in `ahead`.
    ///
    /// Answers whether it did: a member that may not be batched, or a
    /// batch the encoder would not take a second member for, leaves the
    /// caller to encode this member by itself exactly as before.
    pub(super) fn batch_solid(&mut self, index: usize) -> bool {
        self.ahead_len = 0;
        // The batch before is written, or a boundary discarded it and its
        // unwritten readers wait in `restage`.
        self.ahead_input.clear();
        self.ahead_kept.clear();
        if !self.may_batch(index) {
            return false;
        }
        // No further than a batch can hold, so a set of twenty thousand
        // small members does not rescan the whole list for every batch.
        let ceiling = (index + batch_depth() - 1).min(self.members.len() - 1);
        // No further than the volume now open has room for, because a
        // batch that runs past the boundary has its tail discarded there
        // and encoded again. The room is counted in UNPACKED bytes and a
        // header apiece, which no compressed member's packed output
        // exceeds; an over-estimate costs one discarded tail and never a
        // byte of anybody's output. Outside a volume set the budget is
        // `u64::MAX` and this bounds nothing.
        let mut room = self
            .batch_room()
            .saturating_sub(self.packed_estimate(self.members[index].size));
        let mut last_candidate = index;
        while last_candidate < ceiling && self.may_batch(last_candidate + 1) {
            let next = self.packed_estimate(self.members[last_candidate + 1].size);
            if next > room {
                break;
            }
            room -= next;
            last_candidate += 1;
        }
        // A solid run continues unless this member starts one: the same
        // rule `compress_streaming` follows, and the batch's members
        // after the first always continue, because nothing that could end
        // a run stands between two members of one batch.
        let continues = self.options.solid && self.solid_run;
        if !continues {
            self.encoder
                .as_mut()
                .expect("the encoder was built by compress")
                .reset_history();
        }
        // A run this batch starts takes its class from the first member
        // staged, which is the run's first member and is here whole
        // (`encode::drive::Plan::solid_run`, SPEC-H3 8.1).
        let mut starts = !continues;
        self.ahead_digests.clear();
        let mut staged = 0;
        for member in index..=last_candidate {
            let size = usize::try_from(self.members[member].size)
                .expect("a batched member is at most one window");
            let encoder = self
                .encoder
                .as_ref()
                .expect("the encoder was built by compress");
            if staged > 0 && !encoder.may_stage(size) {
                break;
            }
            // A reader whose pull already FAILED, for a batch a volume
            // boundary then discarded, is not pulled again: a reader is
            // pulled once, and its member returns the error it failed
            // with when the writer reaches it (`Run::take_pull_failed`).
            if self
                .pull_failed
                .as_ref()
                .is_some_and(|(at, _)| *at == member)
            {
                break;
            }
            // Spec G 3.8.3's verdict is taken before a member is staged,
            // and a member the samples STORE ends the batch before itself:
            // the writer writes it stored when it reaches it, and the
            // run's history carries past it (spec G 3.9).
            let judges = self.may_sample(member) && !self.sampled[member];
            match self.members[member].payload {
                Payload::Bytes(data) => {
                    if judges {
                        self.sampled[member] = true;
                        if self.samples_store(member, data) {
                            self.stored_by_sample[member] = true;
                            break;
                        }
                    }
                    let encoder = self
                        .encoder
                        .as_mut()
                        .expect("the encoder was built by compress");
                    if std::mem::take(&mut starts) {
                        encoder.start_member(data, data.len() as u64);
                    }
                    encoder.stage(data, true);
                    let out = self.lend_packed(data.len() as u64);
                    self.encoder
                        .as_mut()
                        .expect("the encoder was built by compress")
                        .lend_out(out);
                    self.ahead_digests.push(None);
                }
                Payload::Reader { .. } => {
                    // Pulled whole, here, in `add` order: `may_batch`
                    // says why that is sound, and the pull is the one
                    // the windowed encode would have made of a member
                    // of one window. Its bytes join the history as they
                    // are staged, so the pulled buffer goes straight
                    // back to be pulled into again.
                    debug_assert!(
                        self.prefetched.front().is_none_or(|(at, _)| *at >= member),
                        "a prefetched reader is taken in add order"
                    );
                    // Pulled, judged and staged once already, by a batch a
                    // volume boundary discarded before the writer reached
                    // this member (`Run::next_volume`): staged again from
                    // the bytes kept, and nothing is pulled.
                    if self.restage.front().is_some_and(|(at, _)| *at == member) {
                        let (_, (range, digest)) = self.restage.pop_front().expect("just looked");
                        self.ahead_digests.push(Some(digest));
                        let encoder = self
                            .encoder
                            .as_mut()
                            .expect("the encoder was built by compress");
                        let bytes = &self.restage_buf[range.clone()];
                        if std::mem::take(&mut starts) {
                            encoder.start_member(bytes, bytes.len() as u64);
                        }
                        encoder.stage(bytes, true);
                        let size = self.members[member].size;
                        let out = self.lend_packed(size);
                        self.encoder
                            .as_mut()
                            .expect("the encoder was built by compress")
                            .lend_out(out);
                        let start = self.ahead_input.len();
                        self.ahead_input.extend_from_slice(&self.restage_buf[range]);
                        self.ahead_kept
                            .push((member, (start..self.ahead_input.len(), digest)));
                        if self.restage.is_empty() {
                            self.restage_buf.clear();
                        }
                        note_reader_batched(true);
                        staged += 1;
                        continue;
                    }
                    if let Some((at, _)) = self.prefetched.front() {
                        if *at == member {
                            // Judged beside the flush that pulled it. One
                            // the samples store stays where it was pulled
                            // to until the writer reaches it
                            // (`Run::claim_prefetched`).
                            if self.stored_by_sample[member] {
                                break;
                            }
                            let (_, pulled) = self.prefetched.pop_front().expect("just looked");
                            match pulled {
                                Ok((range, digest)) => {
                                    self.ahead_digests.push(Some(digest));
                                    if self.options.volume_set() {
                                        let start = self.ahead_input.len();
                                        self.ahead_input
                                            .extend_from_slice(&self.prefetch_buf[range.clone()]);
                                        self.ahead_kept.push((
                                            member,
                                            (start..self.ahead_input.len(), digest),
                                        ));
                                    }
                                    let encoder = self
                                        .encoder
                                        .as_mut()
                                        .expect("the encoder was built by compress");
                                    let bytes = &self.prefetch_buf[range];
                                    if std::mem::take(&mut starts) {
                                        encoder.start_member(bytes, bytes.len() as u64);
                                    }
                                    encoder.stage(bytes, true);
                                    let size = self.members[member].size;
                                    let out = self.lend_packed(size);
                                    self.encoder
                                        .as_mut()
                                        .expect("the encoder was built by compress")
                                        .lend_out(out);
                                }
                                Err(error) => {
                                    self.pull_failed = Some((member, error));
                                    break;
                                }
                            }
                            if self.prefetched.is_empty() {
                                self.prefetch_buf.clear();
                            }
                            note_reader_batched(false);
                            staged += 1;
                            continue;
                        }
                    }
                    // The batch's first member may have been pulled to
                    // be sampled already (`Run::sample_solid`).
                    let held = match self.pulled_ahead.take() {
                        Some((at, bytes)) if at == member => Some(bytes),
                        other => {
                            self.pulled_ahead = other;
                            None
                        }
                    };
                    let pulled = match held {
                        Some(bytes) => Ok(bytes),
                        None => self.pull_whole(member),
                    };
                    let bytes = match pulled {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            self.pull_failed = Some((member, error));
                            break;
                        }
                    };
                    if judges {
                        self.sampled[member] = true;
                        if self.samples_store(member, &bytes) {
                            self.stored_by_sample[member] = true;
                            self.prefix.hold(member, bytes);
                            break;
                        }
                    }
                    let digest = {
                        let mut digest = self.new_digest();
                        digest.update(&bytes);
                        digest.finish()
                    };
                    self.ahead_digests.push(Some(digest));
                    if self.options.volume_set() {
                        let start = self.ahead_input.len();
                        self.ahead_input.extend_from_slice(&bytes);
                        self.ahead_kept
                            .push((member, (start..self.ahead_input.len(), digest)));
                    }
                    let encoder = self
                        .encoder
                        .as_mut()
                        .expect("the encoder was built by compress");
                    if std::mem::take(&mut starts) {
                        encoder.start_member(&bytes, bytes.len() as u64);
                    }
                    encoder.stage(&bytes, true);
                    let out = self.lend_packed(bytes.len() as u64);
                    self.encoder
                        .as_mut()
                        .expect("the encoder was built by compress")
                        .lend_out(out);
                    self.keep_spare(bytes);
                    note_reader_batched(false);
                }
            }
            staged += 1;
        }
        if staged == 0 {
            return false;
        }
        // The next batch's readers are pulled while this one is encoded,
        // unless this batch already met a failed pull, or members pulled
        // ahead before are still waiting: a batch ends at a directory or
        // an empty member where a pull ahead does not, so what is waiting
        // is the next batch's already.
        // The readers after this batch, and the verdicts spec G 3.8.3
        // owes them, are taken by this thread while the pool encodes the
        // batch (`pull_ahead`).
        // Nor while readers a boundary discarded still wait to be staged
        // again: they are pulled already, and the list would name them.
        let next = if self.pull_failed.is_some()
            || !self.prefetched.is_empty()
            || !self.restage.is_empty()
        {
            Ahead::default()
        } else {
            self.ahead_plan(index + staged)
        };
        let checksum = self.options.checksum;
        let Run {
            members,
            encoder,
            ahead,
            prefetched,
            prefetch_buf,
            judges,
            ..
        } = self;
        let encoder = encoder.as_mut().expect("the encoder was built by compress");
        // The buffers change places rather than the bytes: the encoder
        // keeps the ones the writer had and the writer takes the packed
        // output, so a batch of a size already seen allocates nothing.
        while ahead.len() < staged {
            ahead.push(Vec::new());
        }
        let kept = flush_beside(
            || {
                for (slot, packed) in ahead.iter_mut().zip(encoder.flush().iter_mut()) {
                    std::mem::swap(slot, packed);
                }
            },
            next,
            members,
            prefetched,
            prefetch_buf,
            judges,
            checksum,
        );
        self.keep_ahead(kept);
        self.ahead_from = index;
        self.ahead_len = staged;
        // `ahead` is at its fullest here: every member of the batch is
        // held, and each is given up as the writer reaches it.
        self.note_peak();
        staged > 0
    }
}
