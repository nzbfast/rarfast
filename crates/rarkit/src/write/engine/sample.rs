//! The store rule (spec G 3.8.3): the samples that decide whether a
//! member is compressed or stored.

use super::*;

#[cfg(feature = "bench-internals")]
thread_local! {
    /// A test's own floor for the whole-member vote, on this thread.
    pub(super) static WHOLE_VOTE_FROM: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Sets, or with `None` clears, this thread's floor for the whole-member
/// vote in place of `store::WHOLE_VOTE_FROM`: for the tests of that vote,
/// which cannot hand over a member of 4 GiB. No shipped build has it.
#[cfg(feature = "bench-internals")]
pub(crate) fn set_whole_vote_from(from: Option<u64>) {
    WHOLE_VOTE_FROM.with(|floor| floor.set(from));
}

/// The least member voted on across its whole length:
/// `store::WHOLE_VOTE_FROM`, or under the `bench-internals` feature what a
/// test set on this thread.
pub(super) fn whole_vote_from() -> u64 {
    #[cfg(feature = "bench-internals")]
    if let Some(from) = WHOLE_VOTE_FROM.with(std::cell::Cell::get) {
        return from;
    }
    store::WHOLE_VOTE_FROM
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// Spec G 3.8.3's verdict for every member whose source can SEEK
    /// (`write::Payload::Seekable`) and that is large enough for sixteen
    /// seeks to cost it nothing: a member the rule samples of at least
    /// `store::WHOLE_VOTE_FROM`, 4 GiB.
    /// Its sixteen samples are read where they lie across the whole member
    /// (`store::seek_says_store`), its verdict recorded as the walk's own
    /// vote records one (`Run::sample_member` then finds it taken), and
    /// the source returned to the member's start.
    ///
    /// Every seekable payload then becomes the READER it is in every
    /// other respect, this run's first act: nothing after this line sees a
    /// payload that can seek, so no plan, budget or path of the run knows
    /// the difference, and a member whose verdict is what its head's
    /// samples would have given is written byte for byte as a reader's is.
    /// A member under 4 GiB is not sought at all: it is a reader, judged
    /// on its head as before. The budget still charges the head a
    /// reader would hold (`Run::sampled_head`), which such a member no
    /// longer holds, so that no admission moves.
    ///
    /// The votes are taken here, before the first byte is written, by one
    /// judge on the calling thread: a member this size is a handful of
    /// reads, and a set has few of them.
    pub(super) fn vote_whole_members(&mut self) -> Result<()> {
        for index in 0..self.members.len() {
            let Some((reader, crc32)) = self.members[index].seekable.take() else {
                continue;
            };
            let size = self.members[index].size;
            if self.may_sample(index)
                && size >= whole_vote_from()
                && size > store::PREFIX_BYTES as u64
            {
                let most_misses = self.options.store_misses(size);
                // By a judge the run keeps, where no small ceiling of the
                // caller's counts them (`store::Judges`).
                let verdict = if self.small_ceiling().is_none() {
                    self.judges.with_one(most_misses, |judge| {
                        store::seek_says_store(&mut *reader, size, judge)
                    })
                } else {
                    let packed = self.options.store_packed_samples;
                    let mut judge = store::Judge::new(most_misses, packed);
                    store::seek_says_store(&mut *reader, size, &mut judge)
                };
                // A source that fails under the look is named, as one that
                // fails under the read is.
                let verdict =
                    verdict.map_err(|error| error.with_member(self.members[index].name))?;
                if let Some(stores) = verdict {
                    self.sampled[index] = true;
                    self.stored_by_sample[index] = stores;
                }
            }
            self.members[index].payload = Payload::Reader { reader, crc32 };
        }
        self.note_peak();
        Ok(())
    }

    /// [`Run::sampled_head_bytes`]'s figure whatever the policy: the head a
    /// sampled READER member holds where its samples compress. The
    /// default's admission (`Run::alone_bytes`) charges it where no
    /// ceiling was named.
    ///
    /// Where the member's class is read (`Run::reads_class`) the head is
    /// at least the megabyte it is read from (`Run::start_member_run`),
    /// sampled or not.
    pub(super) fn sampled_head(&self, index: usize) -> u64 {
        let member = &self.members[index];
        if member.is_directory || !matches!(member.payload, Payload::Reader { .. }) {
            return 0;
        }
        let span = member.size.min(store::PREFIX_BYTES as u64);
        let class = if self.reads_class() && member.size >= class::HEAD_BYTES as u64 {
            class::HEAD_BYTES as u64
        } else {
            0
        };
        if !self.may_sample(index) {
            return class.min(span);
        }
        let settles = 2 * self.options.store_misses(member.size) as u64 + 1;
        (span * settles / (2 * store::SAMPLES as u64) + store::SAMPLE_BYTES as u64 / 2)
            .max(class)
            .min(span)
    }

    /// Whether this run's encoders read a member's class from its head
    /// (`encode::drive::Plan::for_member`): level 5, unless an option
    /// keeps the level one finder. In a solid set it is the first member
    /// of a run that is read, and this answers for every member, so the
    /// charge that asks it (`Run::sampled_head`) allows a megabyte of a
    /// reader's head for members that are not read too: an upper bound.
    /// What `Encoder::reads_head` answers for a member of a megabyte or
    /// more, from the options alone, so a charge need build no encoder.
    pub(super) fn reads_class(&self) -> bool {
        if self.options.stored() {
            return false;
        }
        self.options.method == 5 && !self.options.level5_tree && !self.options.level5_optimal
    }

    /// Whether member `index` is written STORED: every member of a storing
    /// level, and a member spec G 3.8.3's samples said will not compress.
    pub(super) fn member_stored(&self, index: usize) -> bool {
        self.options.stored() || self.stored_by_sample[index]
    }

    /// The method member `index`'s header declares: 0 for a stored member,
    /// the level otherwise.
    pub(super) fn member_method(&self, index: usize) -> u8 {
        if self.member_stored(index) {
            0
        } else {
            self.options.method
        }
    }

    /// Whether spec G 3.8.3's samples are taken for member `index` at all.
    ///
    /// The rule as decided on 28 Sep 2026 (`write::store`): a COMPRESSED
    /// member of at least `store::LEAST_MEMBER_BYTES`. A member of a SOLID
    /// run is judged like any other since 1 Oct 2026: one the samples
    /// store is written stored where it stands and neither starts nor ends
    /// the run (spec G 3.9), whose history carries past it, and bytes with
    /// nothing in them to compress gave the member after them nothing a
    /// match could use. `WriteOptions::solid_store` off keeps every solid
    /// member in the compressor, as before.
    /// The REFERENCE layout is left out too: its bytes are laid out ahead
    /// of the members (`Run::plan_reference`), from the options alone, and
    /// a verdict taken per member would move a header length that plan has
    /// already counted.
    pub(super) fn may_sample(&self, index: usize) -> bool {
        let member = &self.members[index];
        !self.options.stored()
            && (!self.options.solid || self.options.solid_store)
            && !self.options.reference_layout()
            && !member.is_directory
            && member.size >= store::LEAST_MEMBER_BYTES
    }

    /// Take spec G 3.8.3's decision for member `index`: sample it and
    /// record whether it is written stored.
    ///
    /// Bytes in memory are sampled across the whole member. A READER is
    /// read exactly once, so its first `store::PREFIX_BYTES` are pulled
    /// here, as far as the vote needs, and HELD, and every later pull of
    /// this member reads them back before it reads the reader again
    /// (`store::Prefix`). What that costs is the bytes pulled, until the
    /// member's own path has read them back: for a member that compresses,
    /// up to 9/32 of the span and half a sample from 128 MiB, 3/32 below it
    /// and under `WriteOptions::store_one_miss`; up to the last sample for
    /// one that is stored, which then holds nothing else.
    pub(super) fn sample_member(&mut self, index: usize) -> Result<()> {
        if self.sampled[index] {
            // Judged already, as the team planned a batch; the head of a
            // member the samples STORE is held for this member now
            // (`Run::plan_batch`), and is not to be dropped. One a solid
            // batch pulled ahead and the samples store is taken from
            // where that pull left it.
            self.claim_prefetched(index);
            if self
                .head_ahead
                .as_ref()
                .is_some_and(|(at, ..)| *at == index)
            {
                let (_, head, _) = self.head_ahead.take().expect("just looked");
                self.prefix = head;
            }
            return Ok(());
        }
        self.prefix.clear_up_to(index);
        if !self.may_sample(index) {
            return Ok(());
        }
        if self
            .head_failed
            .as_ref()
            .is_some_and(|(at, _)| *at == index)
        {
            let (_, error) = self.head_failed.take().expect("just looked");
            return Err(error);
        }
        if self.options.solid && self.sample_solid(index)? {
            self.note_peak();
            return Ok(());
        }
        let size = self.members[index].size;
        // A run's verdicts are taken by judges it keeps (`store::Judges`),
        // where no small ceiling counts them (`Run::dial_ceiling`); a solid
        // run's across the pool, which stands idle behind this thread here.
        let kept = self.dial_ceiling().is_none();
        let wide = kept && self.options.solid;
        let most_misses = self.options.store_misses(size);
        // A head pulled beside the flush before, whose leading samples did
        // not settle its vote.
        let led = match self.head_ahead.take() {
            Some((at, head, misses)) if at == index => {
                self.prefix = head;
                Some(misses)
            }
            other => {
                self.head_ahead = other;
                None
            }
        };
        let packed = self.options.store_packed_samples;
        let Run {
            members,
            prefix,
            judges,
            ..
        } = self;
        let stores = match &mut members[index].payload {
            Payload::Bytes(data) if kept => judges.say_store(data, most_misses),
            Payload::Bytes(data) => store::samples_say_store(data, most_misses, packed),
            Payload::Reader { reader, .. } => {
                let len = usize::try_from(size.min(store::PREFIX_BYTES as u64))
                    .expect("the prefix is at most 32 MiB");
                if let Some(misses) = led {
                    prefix.finish_wide(&mut **reader, len, most_misses, judges, misses)?
                } else if wide {
                    prefix.sample_wide(index, &mut **reader, len, most_misses, judges)?
                } else if kept {
                    judges.with_one(most_misses, |judge| {
                        prefix.sample_with(index, &mut **reader, len, judge)
                    })?
                } else {
                    prefix.sample(index, &mut **reader, len, most_misses, packed)?
                }
            }
        };
        self.stored_by_sample[index] = stores;
        // The prefix is at its fullest here, and it is held beside
        // whatever the member's own path holds next.
        self.note_peak();
        Ok(())
    }

    /// Spec G 3.8.3's verdict for member `index` of a SOLID run, where the
    /// writer reaches it with none taken; answers whether this took it
    /// (or left it to the batch), false for a member the caller samples
    /// as it does outside a solid run.
    ///
    /// **Where a solid member's verdict comes from.** A member a batch may
    /// stage (`Run::may_batch`) and that the flush before pulled ahead was
    /// judged BESIDE that flush, by the writing thread, which has nothing
    /// else to do while the pool parses, and is never seen here
    /// (`pull_ahead`); so was the head of a reader longer than a window
    /// that follows such a flush. A batch judges its other members as it
    /// stages them. What is left is the member a batch STARTS at with
    /// nothing pulled ahead, and bytes in memory: no flush is running then
    /// and the pool stands idle behind this thread, so the samples are
    /// packed across it (`Run::samples_store`). A reader is
    /// pulled whole first, which is the pull the batch would have made (it
    /// is at most one window), so the whole member is the span:
    ///
    /// - one the samples STORE is held for the stored path
    ///   (`store::Prefix::hold`), its reader having nothing left;
    /// - one they compress is kept for the batch (`Run::pulled_ahead`).
    ///
    /// A pull ahead that FAILED is left for the batch, which reports it
    /// where a member at a time would have. A reader LONGER than a window
    /// that no flush sampled ahead is the caller's, in a volume set as in
    /// one archive: its head is pulled as far as the vote needs and held
    /// (`store::Prefix::sample_wide`).
    pub(super) fn sample_solid(&mut self, index: usize) -> Result<bool> {
        if let Payload::Bytes(data) = self.members[index].payload {
            self.sampled[index] = true;
            self.stored_by_sample[index] = self.samples_store(index, data);
            return Ok(true);
        }
        if !self.may_batch(index) {
            return Ok(false);
        }
        // Its pull failed in a batch that reached it before the writer
        // did: left for the member's own encode, which returns that error
        // (`Run::take_pull_failed`); the reader is not pulled again.
        if self
            .pull_failed
            .as_ref()
            .is_some_and(|(at, _)| *at == index)
        {
            return Ok(true);
        }
        if self.prefetched.front().is_some_and(|(at, _)| *at == index) {
            debug_assert!(
                matches!(self.prefetched.front(), Some((_, Err(_)))),
                "a member pulled ahead was judged beside the flush"
            );
            return Ok(true);
        }
        let bytes = self.pull_whole(index)?;
        self.sampled[index] = true;
        if self.samples_store(index, &bytes) {
            self.stored_by_sample[index] = true;
            self.prefix.hold(index, bytes);
        } else {
            self.pulled_ahead = Some((index, bytes));
        }
        Ok(true)
    }

    /// Whether the samples of `span`, a solid member's whole bytes, say it
    /// is written stored: `store::samples_say_store`'s verdict, taken
    /// across the pool where the caller named no ceiling, since nothing
    /// else is running on it while this thread asks. Under a CALLER'S
    /// ceiling the samples are packed here, one at a time, because each
    /// sample packed at once is an encoder's working memory the ceiling's
    /// sums do not count, and so is a judge kept between verdicts.
    pub(super) fn samples_store(&self, index: usize, span: &[u8]) -> bool {
        let most_misses = self.options.store_misses(self.members[index].size);
        if self.dial_ceiling().is_some() {
            store::samples_say_store(span, most_misses, self.options.store_packed_samples)
        } else {
            self.judges.say_store_wide(span, most_misses)
        }
    }
}
