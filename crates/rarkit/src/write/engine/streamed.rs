//! The streamed walk (spec G 3.7.3 and 3.5): a member whose packed bytes
//! are placed a window at a time, in fragments as the volumes fill.

use super::*;

// The slack multiple a streamed member of a non-solid run with no ceiling
// takes, which a test may set to the shipped `HISTORY_SLACK_MULTIPLE` to
// compare such a run byte for byte with one under a ceiling; and the
// multiple the last streamed member on this thread ran at.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static STREAMED_SLACK: std::cell::Cell<usize> =
        const { std::cell::Cell::new(crate::encode::drive::STREAMED_SLACK_MULTIPLE) };
    pub(super) static LAST_SLACK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// [`crate::encode::drive::STREAMED_SLACK_MULTIPLE`], or in a test the
/// multiple [`with_streamed_slack`] set.
pub(super) fn streamed_slack() -> usize {
    #[cfg(feature = "bench-internals")]
    {
        STREAMED_SLACK.with(std::cell::Cell::get).max(1)
    }
    #[cfg(not(feature = "bench-internals"))]
    {
        crate::encode::drive::STREAMED_SLACK_MULTIPLE
    }
}

/// Runs `work` with a streamed member's slack multiple set to `multiple`
/// on this thread. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_streamed_slack<T>(multiple: usize, work: impl FnOnce() -> T) -> T {
    let was = STREAMED_SLACK.with(|cell| cell.replace(multiple));
    let result = work();
    STREAMED_SLACK.with(|cell| cell.set(was));
    result
}

/// The slack multiple the last member streamed on this thread ran at;
/// zero before any. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn last_streamed_slack() -> usize {
    LAST_SLACK.with(std::cell::Cell::get)
}

// The working limit a member's held-whole write is compared with where
// the caller named no ceiling (spec G 3.5's held-member rule),
// which a test may set so that a member of a few MiB takes the
// walk a member of hundreds does. `None`, and always without
// `bench-internals`, is the policy's own `working_limit`.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static STREAM_ABOVE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// The working limit a member's held-whole write must fit for the member
/// to be held where the caller named no ceiling: `working_limit`, the
/// policy's own (`MemoryPolicy::process_default`'s under the command
/// line), or in a test the figure [`with_stream_above`] set.
pub(super) fn stream_above(working_limit: u64) -> u64 {
    #[cfg(feature = "bench-internals")]
    {
        STREAM_ABOVE
            .with(std::cell::Cell::get)
            .unwrap_or(working_limit)
    }
    #[cfg(not(feature = "bench-internals"))]
    {
        working_limit
    }
}

/// Runs `work` with this thread's streaming threshold set to `bytes`.
/// This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_stream_above<T>(bytes: u64, work: impl FnOnce() -> T) -> T {
    let was = STREAM_ABOVE.with(|cell| cell.replace(Some(bytes)));
    let result = work();
    STREAM_ABOVE.with(|cell| cell.set(was));
    result
}

// How many members this thread has written by the STREAMED walk
// (`Run::write_member_streamed`), so that a test can say the path it
// means to measure was the path taken. Nothing in a shipped build carries
// it, and nothing outside this repository's tests can read it.
#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static STREAMED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One member written by the streamed walk.
pub(super) fn note_streamed() {
    #[cfg(feature = "bench-internals")]
    STREAMED.with(|count| count.set(count.get() + 1));
}

/// How many members the streamed walk has written on this thread since
/// [`reset_streamed_members`]. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn streamed_members() -> usize {
    STREAMED.with(std::cell::Cell::get)
}

/// Starts the count in [`streamed_members`] again from zero.
#[cfg(feature = "bench-internals")]
pub(crate) fn reset_streamed_members() {
    STREAMED.with(|count| count.set(0));
}

/// The encode of a member whose packed output is consumed AS THE ENCODER
/// PRODUCES IT, rather than being held whole (`Run::write_member_streamed`).
///
/// It is the last term of a write's working memory that followed the
/// ARCHIVE rather than the options. `Run::packed` holds a member's whole
/// packed stream because a member header's packed size field IS that
/// length and the header goes down first; this walk lays the header down
/// with spec G 3.5's reserved field, streams the encoder's chunks
/// straight out, and corrects the header where it lies once the fragment
/// is closed. What is pending at any moment is ONE chunk of the
/// encoder's output, which follows the window and so follows the
/// options.
#[derive(Default)]
pub(super) struct StreamState {
    /// The packed bytes the encoder has produced and the walk has not
    /// yet placed: one chunk, never the member's stream.
    pub(super) pending: Vec<u8>,
    /// How many of `pending` have gone out.
    pub(super) sent: usize,
    /// Input bytes handed to the encoder for this member so far.
    pub(super) pulled: u64,
    /// This member's packed bytes placed in the fragments ALREADY CLOSED,
    /// which is what the next fragment's reserved width is taken from
    /// (`Run::fragment_reserve`): at a fragment's start it is the volumes'
    /// fills, the same however the member was pulled.
    pub(super) placed: u64,
    /// Whether the encoder has had this member's LAST input chunk.
    pub(super) done: bool,
    /// Windows staged in the encoder and not yet flushed, where the walk
    /// stages them (`Run::stream_pull`).
    pub(super) staged: usize,
    /// Whether the member's segment team hands its stretches over rolling
    /// ([`Roll`]), a stretch a pull.
    pub(super) rolls: bool,
    /// Whether the member's windows are read ahead of its one engine, and
    /// where that reading stands ([`WindowsAhead`]).
    pub(super) reads_ahead: bool,
    pub(super) ahead: WindowsAhead,
    /// The packed size field's width for the fragment being laid down, in
    /// cases (b) and (c), where it is chosen a fragment at a time
    /// (`Run::fragment_reserve`); `None` in case (a) and outside the walk.
    pub(super) reserve: Option<usize>,
    /// Whether a member's encode is in flight, which is what keeps a
    /// volume boundary from resetting the history underneath it
    /// (`Run::next_volume`).
    pub(super) in_flight: bool,
    /// Whether this member's walk crossed a volume boundary, so that the
    /// history it carried across it is dropped when the member ends -
    /// which is where the member-at-a-time walk drops it, and is why the
    /// two produce the same archive.
    pub(super) crossed: bool,
    /// Whether the member in flight runs at the streamed slack
    /// (`Run::write_member_streamed`), which the segment team's engines
    /// are set to as the run's own is.
    pub(super) wide_slack: bool,
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// The history's slack, in dictionaries, that a member above one
    /// window is encoded under by the held walk
    /// (`Run::compress_streaming`): the streamed slack for a non-solid
    /// member where no ceiling was named and the dictionary is long
    /// enough for it, the shipped slack otherwise.
    pub(super) fn streamed_slack_multiple(&self) -> usize {
        if !self.options.solid
            && self.small_ceiling().is_none()
            && self.dictionary >= crate::encode::drive::STREAMED_SLACK_LEAST_DICTIONARY as u64
        {
            streamed_slack()
        } else {
            crate::encode::drive::HISTORY_SLACK_MULTIPLE
        }
    }

    /// Whether member `index` is written by the STREAMED walk: its packed
    /// bytes cut into fragments as the encoder produces them, rather than
    /// held whole and cut afterwards (`Run::write_member_streamed`).
    ///
    /// Every condition is a thing that makes the walk WRONG rather than
    /// merely slower, and there are two kinds of them.
    ///
    /// **The header's length must not move.** The walk lays a fragment's
    /// header down before it knows what the fragment holds and corrects
    /// it where it lies, so the corrected header has to be exactly as
    /// long as the one it replaces. That is what the format conditions
    /// below are about, and they differ by family:
    ///
    /// - RAR 5 writes the packed size as a vint, so its width follows the
    ///   value. Spec G 3.5's reserved field fixes it - and only on the
    ///   solid volume-set path 3.5 names, which is what
    ///   `Run::packed_reserve` answers - so the walk also checks that the
    ///   reservation covers the LARGEST value this fragment could carry,
    ///   which is the volume's cap. Where it would not, this member takes
    ///   the old walk and no field is emitted that could not be corrected
    ///   to the true value, which is 3.5's own rule.
    /// - RAR 4 writes a fixed 32 bit packed size with a second word
    ///   behind a flag (spec G 3.14.3), so the length turns on that flag
    ///   alone. It is fixed when the member's unpacked size already sets
    ///   it, or when no fragment can reach the 4 GiB the flag marks.
    ///
    /// **The output must be able to take the correction**, which is
    /// `VolumeOut::can_patch`. On one that cannot, spec G 3.7.2's
    /// fallback holds a HEADER and never a payload, so the whole point of
    /// this walk would be lost: the member takes the old one.
    ///
    /// **The packed bytes are this walk's own.** It hands the encoder one
    /// WINDOW at a time, which is spec G 3.7.3's walk and is what a solid
    /// member already takes (`Run::compress_streaming`);
    /// `Run::compress`'s shortcut for a non-solid member whose bytes are
    /// in memory encodes it as ONE region over its own slice instead, and
    /// a region and a chain of windows are not the same packed stream -
    /// measured, on the RAR 4 family. So a member that takes this walk
    /// stands that shortcut aside, and `Run::compress` asks THIS
    /// predicate whether it does.
    ///
    /// **Which is why the two walks can now write different bytes for one
    /// member, and exactly where.** The rule as first built kept the
    /// bytes equal whatever the output by standing the shortcut aside for
    /// every case (b) member, and that cost about 1.43x of wall on a
    /// compressed non-solid volume create, because one 32 MiB parse wave
    /// became four 8 MiB ones. It was narrowed on 20 Sep 2026: case
    /// (b) streams only under a caller's ceiling
    /// (`Run::over_ceiling`), and a ceiling that
    /// cannot be kept - the output cannot patch - is held whole rather
    /// than refused. So for a case (b) member a patchable output and a
    /// non-patchable one CAN differ, in the packed size field's width and
    /// in the packed stream itself. Spec G 3.5 grants exactly that
    /// exception and nothing wider, and `VolumeOut::can_patch`'s own
    /// documentation says so.
    ///
    /// The rest are scope. Only a member larger than ONE WINDOW is
    /// streamed, because everything smaller is already bounded by the
    /// window and batching it is what keeps the parse wide
    /// (`Run::may_batch`). A SOLID VOLUME SET has taken this walk since
    /// 19 Sep 2026, whatever the policy (case a). A member of a NON-SOLID
    /// set (case b) or of ONE archive (case c) takes it where holding it
    /// whole would pass a ceiling the caller named (mode 2),
    /// and, since 28 Sep 2026, where the caller named none
    /// and holding it whole would not fit the policy's own
    /// `working_limit`, its packed bytes counted twice (spec G 3.5's
    /// held-member rule of 30 Sep 2026, which replaced the
    /// packed bound alone against `DEFAULT_LIMIT`): a big member is
    /// held whole nowhere an output can take the correction, so that a
    /// write's memory follows the options and not the archive,
    /// and the measured price of that is a digit of one field, at
    /// the held walk's wall once the walk stages its windows. An
    /// ENCRYPTED member streams too (since 28 Sep 2026): the walk cuts it
    /// where the held walk cuts it, looking fewer than a cipher block's
    /// bytes ahead for what the held walk reads off the member's packed
    /// length (`Run::stream_fragments`), and its field is reserved to
    /// cover the padded last block.
    pub(super) fn streams_packed(&self, index: usize) -> bool {
        if !self.out.can_patch() {
            return false;
        }
        if self.options.reference_layout() || self.member_stored(index) {
            return false;
        }
        let member = &self.members[index];
        if member.is_directory || member.size <= self.window_bytes() as u64 {
            return false;
        }
        // An encrypted fragment's field can carry a cipher block's padding
        // more than the room it was given (`Run::stream_fragments`).
        let pad = if self.options.password.is_some() {
            CIPHER_BLOCK as u64
        } else {
            0
        };
        if self.is_case_a() {
            // Case (a), every member of a solid volume set, whatever the
            // policy says, at the member's reserved width,
            // which has to cover the largest fragment a volume can hold.
            let Some(ceiling) = self.fragment_ceiling() else {
                return false;
            };
            return match self.options.format {
                // `Run::reserve_width` and not `Run::packed_reserve`: the
                // latter asks whether this member STREAMS, which is the
                // question being answered here.
                WriteFormat::Rar5 => match self.reserve_width(index) {
                    Some(width) => width >= rar5::vint_width_of(ceiling.saturating_add(pad)),
                    None => false,
                },
                WriteFormat::Rar4(_) => {
                    member.size >= R4_SIZE_FIELD_LIMIT
                        || ceiling.saturating_add(pad) < R4_SIZE_FIELD_LIMIT
                }
            };
        }
        // Cases (b), a member of a non-solid volume set, and (c), a member
        // of one archive (since 28 Sep 2026): streamed where
        // holding it whole would pass a ceiling the caller NAMED (mode
        // 2), and, where the caller named none, wherever the
        // same held-whole sum passes the policy's own `working_limit`
        // (spec G 3.5's held-member rule: the sum with its
        // packed bytes counted twice, where the first rule compared the
        // packed bound alone with `DEFAULT_LIMIT` and held members that
        // peaked at 750 MiB). A RAR 5 field is reserved a fragment at a
        // time (`Run::fragment_reserve`) and so always covers its value;
        // a RAR 4 one is fixed, and its length turns on the high-size
        // flag alone, which the member's size must already settle or no
        // fragment reach.
        let streams = match self.caller_ceiling() {
            Some(_) => self.over_ceiling(index).is_some(),
            None => self.held_whole_bytes(index) > stream_above(self.held_member_limit()),
        };
        if !streams {
            return false;
        }
        match self.options.format {
            WriteFormat::Rar5 => true,
            WriteFormat::Rar4(_) => {
                let most = self
                    .fragment_ceiling()
                    .unwrap_or(u64::MAX)
                    .min(self.packed_bound(index))
                    .saturating_add(pad);
                member.size >= R4_SIZE_FIELD_LIMIT || most < R4_SIZE_FIELD_LIMIT
            }
        }
    }

    /// Whether this run's streamed members are spec G 3.5's case (a): a
    /// SOLID VOLUME SET, whose members stream whatever the policy says and
    /// reserve the member's own width. Every other streamed member is case
    /// (b) or (c) and reserves a fragment at a time.
    pub(super) fn is_case_a(&self) -> bool {
        self.options.solid && self.options.volume_set()
    }

    /// One more window of the streamed member: pull the input, hash it,
    /// and hand it to the encoder. What comes back REPLACES `pending`, so
    /// nothing accumulates across chunks.
    pub(super) fn stream_pull(
        &mut self,
        index: usize,
        want: u64,
        window: usize,
        digest: &mut Running,
    ) -> Result<()> {
        // Windows are STAGED and parsed several at once where the caller
        // set no ceiling, exactly as `Run::compress_streaming` stages the
        // windows of a member it holds (`stage_window` says why that
        // moves no byte); under a ceiling a flush is one window, which is
        // what `Run::beside_team_bytes` counts.
        let depth = self.staged_depth();
        debug_assert!(
            !self.stream.done,
            "a chunk was pulled after the member's last"
        );
        // What has gone out is dropped; what has not is KEPT in front of
        // what comes next, which is how an encrypted walk looks further
        // ahead than one chunk (`Run::rest_fits`). Outside that the walk
        // pulls only once everything pending has gone, and this is a
        // clear.
        let sent = self.stream.sent;
        self.stream.pending.drain(..sent);
        self.stream.sent = 0;
        let before = self.stream.pending.len();
        // Until a flush has produced something to place, or the member
        // has ended: a staged window's packed bytes exist only once its
        // batch is parsed.
        while self.stream.pending.len() == before && !self.stream.done {
            // The segment team's round, where the member runs on one
            // ([`Segments`]): several stretches' packed bytes at once.
            #[cfg(feature = "parallel")]
            if self.segments.width >= 2 && self.stream.rolls {
                // The rolling hand-off, a stretch a pull: the walk places
                // one while the engines encode the ones after it. Every cut
                // below is a function of the packed stream and of the
                // member's declared size (`Run::fragment_reserve`), never
                // of how much one pull hands over.
                if self.segments.roll.is_none() {
                    let slack = if self.stream.wide_slack {
                        streamed_slack()
                    } else {
                        crate::encode::drive::HISTORY_SLACK_MULTIPLE
                    };
                    self.roll_start(want, window, depth, slack);
                }
                let mut pending = std::mem::take(&mut self.stream.pending);
                let outcome = self.roll_on(index, digest, &mut pending, true);
                self.stream.pending = pending;
                outcome?;
                let roll = self.segments.roll.as_ref().expect("a roll in flight");
                self.stream.pulled = roll.out_at;
                self.stream.done = roll.emitted == roll.plan.len();
                self.note_peak();
                continue;
            }
            #[cfg(feature = "parallel")]
            if self.segments.width >= 2 {
                let slack = if self.stream.wide_slack {
                    streamed_slack()
                } else {
                    crate::encode::drive::HISTORY_SLACK_MULTIPLE
                };
                let mut pending = std::mem::take(&mut self.stream.pending);
                let round = self.segment_round(
                    index,
                    want,
                    window,
                    self.stream.pulled,
                    digest,
                    depth,
                    slack,
                    &mut pending,
                );
                self.stream.pending = pending;
                self.stream.pulled = round?;
                self.stream.done = self.stream.pulled == want;
                self.note_peak();
                continue;
            }
            if self.stream.reads_ahead {
                // The windows read ahead ([`WindowsAhead`]): `stage_window`'s
                // own steps, the flush before a window run beside the read
                // of the windows after it.
                let Run {
                    members,
                    scratch,
                    encoder,
                    stream,
                    prefix,
                    ..
                } = self;
                let encoder = encoder
                    .as_mut()
                    .expect("the encoder was built before the walk");
                let room = (want - stream.pulled).min(window as u64) as usize;
                let last = stream.pulled + room as u64 == want;
                let StreamState {
                    pending,
                    staged,
                    ahead,
                    pulled,
                    done,
                    ..
                } = stream;
                if *staged >= depth || (*staged > 0 && !encoder.may_stage(room)) {
                    let was = *staged;
                    let filtered = encoder.plans_filters();
                    let next = *pulled;
                    beside_with(
                        || flush_windows(encoder, pending, false, staged),
                        |_| {
                            read_windows(
                                &mut members[index],
                                prefix,
                                index,
                                scratch,
                                ahead,
                                want,
                                window,
                                depth,
                                digest,
                            );
                            // The plans of the windows just read, while
                            // the pool still parses (`plan_ahead`).
                            if filtered {
                                plan_ahead(scratch, ahead, next, want, window);
                            }
                        },
                    );
                    note_flush_width(was);
                }
                if ahead.tail - ahead.head < room {
                    // Nothing read ahead: read as it is staged.
                    read_windows(
                        &mut members[index],
                        prefix,
                        index,
                        scratch,
                        ahead,
                        want,
                        window,
                        1,
                        digest,
                    );
                    if ahead.tail - ahead.head < room {
                        return Err(ahead
                            .failed
                            .take()
                            .unwrap_or_else(|| refuse("a window read ahead came short")));
                    }
                }
                let planned = ahead.take_plan(*pulled);
                encoder.stage_window_planned(
                    &scratch[ahead.head..ahead.head + room],
                    last,
                    *pulled,
                    planned,
                    &mut ahead.spare_plans,
                );
                ahead.head += room;
                *staged += 1;
                *pulled += room as u64;
                if last {
                    flush_windows(encoder, pending, false, staged);
                }
                *done = last;
                self.note_peak();
                continue;
            }
            let Run {
                members,
                scratch,
                encoder,
                stream,
                prefix,
                ..
            } = self;
            let encoder = encoder
                .as_mut()
                .expect("the encoder was built before the walk");
            let room = (want - stream.pulled).min(window as u64) as usize;
            scratch.clear();
            match &mut members[index].payload {
                Payload::Bytes(data) => {
                    let at = stream.pulled as usize;
                    scratch.extend_from_slice(&data[at..at + room]);
                }
                Payload::Reader { reader, .. } => {
                    scratch.resize(room, 0);
                    let mut filled = 0;
                    while filled < room {
                        let read = prefix
                            .read(index, &mut **reader, &mut scratch[filled..room])
                            .map_err(Error::from)?;
                        if read == 0 {
                            return Err(Error::new(ErrorKind::Truncated));
                        }
                        filled += read;
                    }
                }
            }
            let base = stream.pulled;
            stream.pulled += room as u64;
            digest.update(scratch);
            let last = stream.pulled == want;
            // The encoder keeps the history and the index over it, so this
            // window pays only for its own bytes (spec H3 section 4).
            if depth > 1 {
                stage_window(
                    encoder,
                    scratch,
                    last,
                    base,
                    &mut stream.pending,
                    false,
                    depth,
                    &mut stream.staged,
                );
            } else {
                encoder.chunk(scratch, last, &mut stream.pending, base);
            }
            stream.done = last;
            // What is pending and the window still in `scratch`: the
            // streamed walk's high point, and the one that must NOT follow
            // the member, which is what `streamed_packed_member.rs` pins.
            // Staged, what is pending is one batch's packed bytes, which
            // `Engine::batch_cap` bounds and the member does not.
            self.note_peak();
        }
        Ok(())
    }

    /// The payload room one fragment of the streamed member has in the
    /// volume now open, opening a fresh volume when this one has none
    /// left. Answers the room and the fragment header's length.
    ///
    /// **This is `Run::fit_header` with nothing to solve.** That one
    /// solves the header's length against the room because the length
    /// follows the packed size the header declares; here the packed size
    /// field is reserved at a width the value cannot exceed
    /// (`Run::streams_packed`), so the header is the same length for
    /// every fragment of this member and the room is a subtraction. The
    /// FILE budget stays exact to the byte, which is what
    /// `tests/volume_budget.rs` holds the writer to.
    pub(super) fn stream_room(&mut self, index: usize) -> Result<(u64, usize)> {
        let file_budget = self.options.volume_file_size.is_some();
        for attempt in 0..2 {
            self.refresh_budget();
            self.stream.reserve = (!self.is_case_a()).then(|| self.fragment_reserve(index));
            let mut scratch = std::mem::take(&mut self.header_scratch);
            self.member_header(
                index,
                Fragment::First,
                0,
                self.placeholder_digest(index),
                &mut scratch,
            );
            let header_len = scratch.bytes.len();
            self.header_scratch = scratch;
            let room = if file_budget {
                self.budget.saturating_sub(self.on_disk(header_len))
            } else {
                self.budget
            };
            if room > 0 {
                return Ok((room, header_len));
            }
            // A volume that has already taken something can be closed and
            // the fragment started in a fresh one; a FRESH volume that
            // cannot hold a header and a byte is a cap no run can honour.
            if attempt == 1 || self.out.position() <= self.head_bytes {
                return Err(refuse(
                    "a volume file size too small for this member's own header",
                ));
            }
            self.next_volume()?;
        }
        unreachable!("the loop above either answers or refuses")
    }

    /// Spec G 3.7.3 and 3.5 together, for a member whose packed output
    /// the writer will not hold: the FRAGMENT WALK consumes the encoder's
    /// chunks as they arrive.
    ///
    /// The member-at-a-time walk in [`Run::write_member`] encodes the
    /// whole member first, because a member header's packed size field IS
    /// that length and the header goes down first. That buffer was the
    /// last term of a write's working memory to follow the ARCHIVE rather
    /// than the options: everything else - the encoder's history, the
    /// blocks in flight, a batch's pending output, the copy buffer, one
    /// window - is bounded by the dictionary and the batch cap.
    ///
    /// This walk closes it with the two things 3.5 describes and one it
    /// does not:
    ///
    /// 1. the header is laid down with the RESERVED packed size field of
    ///    3.5, whose width does not follow the value, so the header that
    ///    corrects it is exactly as long;
    /// 2. the field is PATCHED where it lies once the fragment is closed,
    ///    which is 3.7.2's machinery over an output that said it could
    ///    (`VolumeOut::can_patch`);
    /// 3. and the header's other two unknowns are corrected in the same
    ///    pass, because by then they are known too: whether this is the
    ///    LAST fragment (block flag 0x0010, spec G 3.10.2) and, on the
    ///    last, the WHOLE member's checksum.
    ///
    /// **The one-chunk look-ahead.** A fragment that filled the volume
    /// has still not told the walk whether anything follows it: that is a
    /// question only the encoder can answer, and it answers it by being
    /// asked for the next chunk. So the walk asks, once, before it
    /// decides whether to open another volume - and what it holds while
    /// it waits is that one chunk, which follows the window and not the
    /// member. It is the whole of what this path holds.
    pub(super) fn write_member_streamed(&mut self, index: usize) -> Result<()> {
        let want = self.members[index].size;
        let window = self.window_bytes();
        let continues = self.options.solid && self.solid_run;
        // One cipher per member, its initialisation vector drawn HERE, one
        // draw per member in `add` order and before any header of this
        // member is written, which is where the held walk draws it
        // (`Run::write_member`), so a seeded run draws the same bytes in
        // the same order down either walk (spec G 3.13).
        self.crypt = MemberCrypt::new(&self.key, &mut self.draw)?;

        self.ensure_encoder();
        if !continues {
            self.start_member_run(index)?;
        }
        self.scratch.reserve(window);
        self.stream.pending.clear();
        self.stream.sent = 0;
        self.stream.pulled = 0;
        self.stream.placed = 0;
        self.stream.done = false;
        self.stream.staged = 0;
        self.stream.reserve = None;
        self.stream.crossed = false;
        self.stream.in_flight = true;
        note_streamed();
        // The held walk's slack, under the held walk's own condition
        // (`Run::compress_streaming`), so that a member streamed with no
        // ceiling is the same packed stream as the member held whole and
        // only the size field's width differs.
        let wide_slack = !self.options.solid
            && self.small_ceiling().is_none()
            && self.dictionary >= crate::encode::drive::STREAMED_SLACK_LEAST_DICTIONARY as u64;
        if wide_slack {
            self.encoder
                .as_mut()
                .expect("the encoder was just built")
                .set_slack_multiple(streamed_slack());
        }
        self.stream.wide_slack = wide_slack;
        self.segments.width = self.segment_width(index);
        #[cfg(feature = "parallel")]
        {
            self.stream.rolls = self.rolls() && self.roll_fits_streamed(window);
        }
        self.stream.ahead = WindowsAhead::default();
        self.stream.reads_ahead = self.segments.width < 2 && self.windows_ahead();
        if self.stream.reads_ahead {
            self.size_scratch_ahead(want);
            note_window_ahead();
        }

        let outcome = self.stream_fragments(index, want, window);
        // Before the encoder is touched again: the hand-off holds it.
        #[cfg(feature = "parallel")]
        self.roll_end();
        self.stream.rolls = false;
        self.stream.reads_ahead = false;
        self.stream.ahead = WindowsAhead::default();
        self.segments.width = 0;
        // A walk that ended in an error (a reader that failed) can leave
        // windows staged in the engine and never flushed. They go with the
        // member, before the slack is put back and the history dropped
        // below, both of which want nothing staged: until 2 Oct 2026 a
        // debug build panicked there (`Engine::reset_history`) where a
        // release build returned the reader's error.
        if outcome.is_err() && self.stream.staged > 0 {
            if let Some(encoder) = &mut self.encoder {
                let mut dropped = std::mem::take(&mut self.stream.pending);
                flush_windows(encoder, &mut dropped, false, &mut self.stream.staged);
                self.stream.pending = dropped;
            }
        }

        if wide_slack {
            if let Some(encoder) = &mut self.encoder {
                encoder.set_slack_multiple(crate::encode::drive::HISTORY_SLACK_MULTIPLE);
            }
        }
        self.stream.reserve = None;

        // The history this member carried over a boundary goes with the
        // member, which is where the member-at-a-time walk drops it.
        if self.stream.crossed {
            if let Some(encoder) = &mut self.encoder {
                encoder.reset_history();
            }
        }
        self.stream.in_flight = false;
        self.stream.pending.clear();
        self.stream.sent = 0;
        self.crypt = None;
        outcome?;

        // A solid run continues from here, exactly as it does for a
        // member the writer held whole.
        self.solid_run = true;
        if let Some(expected) = self.declared_crc32(index) {
            let computed = self
                .unpacked_digest
                .expect("the streamed walk hashes every member's unpacked bytes");
            if !digest_matches(computed, expected) {
                return Err(Error::new(ErrorKind::Corrupt(Corruption::Checksum))
                    .with_member(self.members[index].name));
            }
        }
        self.check_payload_end(index)?;
        self.progress.output(self.delivered)
    }

    /// Whether what member `index` has still to place is at most `n`
    /// bytes, found by pulling until the answer is certain: the pending
    /// bytes pass `n`, or the member ends within them. Only ever asked for
    /// fewer than a cipher block's bytes, so what it holds beyond one
    /// chunk is that many.
    pub(super) fn rest_fits(
        &mut self,
        index: usize,
        want: u64,
        window: usize,
        digest: &mut Running,
        n: u64,
    ) -> Result<bool> {
        loop {
            let unsent = (self.stream.pending.len() - self.stream.sent) as u64;
            if unsent > n {
                return Ok(false);
            }
            if self.stream.done {
                return Ok(true);
            }
            self.stream_pull(index, want, window, digest)?;
        }
    }

    /// Place up to `limit` of the member's packed bytes in the fragment
    /// open now, pulling as needed, and answer how many were placed: fewer
    /// than `limit` only where the member ended first. Under a cipher the
    /// bytes go out enciphered, the chain carrying across calls and a
    /// block short of whole held back until the next (`MemberCrypt::push`),
    /// and the fragment's own checksum is taken over the bytes that land
    /// where spec K 3.7.6 says so (`Run::copy_payload`, the held walk's).
    pub(super) fn place(
        &mut self,
        index: usize,
        want: u64,
        window: usize,
        unpacked: &mut Running,
        fragment_digest: &mut Running,
        limit: u64,
    ) -> Result<u64> {
        let cipher_fragment = self
            .crypt
            .as_ref()
            .is_some_and(MemberCrypt::fragments_digest_ciphertext);
        let mut placed = 0u64;
        while placed < limit {
            if self.stream.sent == self.stream.pending.len() {
                if self.stream.done {
                    break;
                }
                self.stream_pull(index, want, window, unpacked)?;
                continue;
            }
            let take =
                ((limit - placed) as usize).min(self.stream.pending.len() - self.stream.sent);
            let Run {
                stream,
                out,
                crypt,
                cipher_out,
                progress,
                delivered,
                ..
            } = self;
            // One report per chunk, never one per byte and never one
            // that allocates (spec G 3.13).
            for piece in stream.pending[stream.sent..stream.sent + take].chunks(COPY_CHUNK) {
                let written: &[u8] = match crypt {
                    None => piece,
                    Some(crypt) => {
                        crypt.push(piece, cipher_out)?;
                        cipher_out
                    }
                };
                fragment_digest.update(if cipher_fragment { written } else { piece });
                out.write(written)?;
                *delivered += piece.len() as u64;
                progress.output(*delivered)?;
            }
            self.stream.sent += take;
            placed += take as u64;
        }
        Ok(placed)
    }

    /// The fragment loop of [`Run::write_member_streamed`], apart so that
    /// the state it leaves behind is cleaned up on the error path too.
    ///
    /// **Under a cipher it cuts where the held walk cuts** (`Run::write_member`),
    /// which knows the member's packed length and so where it ends; this
    /// walk asks the same three questions and answers each by looking
    /// fewer than a cipher block's bytes ahead (`Run::rest_fits`):
    ///
    /// - a volume with fewer than a cipher block's bytes of room left
    ///   takes the member's rest only if the rest fits in it, and is
    ///   closed otherwise;
    /// - a fragment that is not the member's last holds whole cipher
    ///   blocks, so the chain never carries across a volume, and so is
    ///   placed up to the room rounded down to a block, and is the last
    ///   only if what then remains fits in what is left of the room;
    /// - the last fragment's field is its PADDED length, and its data
    ///   area the padded block the cipher finishes with.
    pub(super) fn stream_fragments(
        &mut self,
        index: usize,
        want: u64,
        window: usize,
    ) -> Result<()> {
        let mut unpacked = self.new_digest();
        let encrypting = self.crypt.is_some();
        // The first chunk, so the loop below never opens a fragment for a
        // member that has nothing left.
        self.stream_pull(index, want, window, &mut unpacked)?;

        let mut first = true;
        let mut packed_total = 0u64;
        loop {
            if encrypting {
                self.refresh_budget();
                let budget = self.budget;
                if budget < CIPHER_BLOCK as u64
                    && !self.rest_fits(index, want, window, &mut unpacked, budget)?
                {
                    self.next_volume()?;
                }
            }
            let (mut room, mut header_len) = self.stream_room(index)?;
            // **In the FILE budget the room is what the cap leaves once
            // the fragment's header is in it, and under a cipher nothing
            // goes into less than a block of it**: a fragment that is not
            // the last holds whole blocks, and a last one is padded to
            // one. The check above reads the budget before the header is
            // paid for, so it does not see this. A header laid here would
            // head a fragment of no bytes, and where a fresh volume has
            // no more room than that, one after another for ever (spec G
            // section 4: no unbounded loop on any caller input).
            let file_budget = self.options.volume_file_size.is_some();
            if encrypting && file_budget && room < CIPHER_BLOCK as u64 {
                let small =
                    || refuse("a volume file size too small for one cipher block of this member");
                if self.out.position() <= self.head_bytes {
                    return Err(small());
                }
                self.next_volume()?;
                (room, header_len) = self.stream_room(index)?;
                if room < CIPHER_BLOCK as u64 {
                    return Err(small());
                }
            }

            // The header goes down saying nothing it does not yet know:
            // a placeholder checksum of the right KIND, a packed size of
            // zero in the RESERVED field, and the fragment shape it will
            // have if the volume fills. Every one of the three is
            // corrected below, in one pass, where the header lies.
            let mut scratch = std::mem::take(&mut self.header_scratch);
            self.member_header(
                index,
                Fragment::First,
                0,
                self.placeholder_digest(index),
                &mut scratch,
            );
            debug_assert_eq!(scratch.bytes.len(), header_len);
            let header_at = self.write_header(&scratch.bytes);
            self.header_scratch = scratch;
            let header_at = header_at?;

            let mut fragment_digest = self.new_digest();
            let last;
            let mut placed;
            if encrypting {
                let whole = room - room % CIPHER_BLOCK as u64;
                placed = self.place(
                    index,
                    want,
                    window,
                    &mut unpacked,
                    &mut fragment_digest,
                    whole,
                )?;
                // What of the room past its whole blocks the member's
                // rest may take. In the PAYLOAD budget, all of it: the
                // budget counts the member's bytes and the padding goes
                // on top, as in the held walk. In the FILE budget, none:
                // the cipher pads a last fragment to a whole block, which
                // would end up to 15 bytes past the room and so past the
                // cap, where the held walk fits the PADDED length
                // (`Run::fit_header`). So there the member ends in this
                // fragment only if it ends inside the whole blocks.
                let tail = if file_budget { 0 } else { room - whole };
                if placed < whole {
                    last = true;
                } else if self.rest_fits(index, want, window, &mut unpacked, tail)? {
                    placed += self.place(
                        index,
                        want,
                        window,
                        &mut unpacked,
                        &mut fragment_digest,
                        tail,
                    )?;
                    last = true;
                } else {
                    last = false;
                }
                if last {
                    self.flush_cipher()?;
                }
            } else {
                placed = self.place(
                    index,
                    want,
                    window,
                    &mut unpacked,
                    &mut fragment_digest,
                    room,
                )?;
                // The look-ahead: is there another byte after this fragment?
                while self.stream.sent == self.stream.pending.len() && !self.stream.done {
                    self.stream_pull(index, want, window, &mut unpacked)?;
                }
                last = self.stream.done && self.stream.sent == self.stream.pending.len();
            }
            // Under a cipher the last fragment's field is its padded
            // length, which is what the cipher wrote.
            let field = if encrypting && last {
                padded_len(placed)
            } else {
                placed
            };

            let fragment = match (first, last) {
                (true, true) => Fragment::Whole,
                (true, false) => Fragment::First,
                (false, true) => Fragment::Last,
                (false, false) => Fragment::Middle,
            };
            // The checksum a fragment carries is its OWN except on the
            // last, which carries the WHOLE member's (spec G 3.10.2) -
            // and a compressed member's whole-member checksum is over its
            // UNPACKED bytes, which this walk took as the windows passed,
            // stored as a cipher stores it (`Run::stored_as`).
            let digest = if last {
                let value = unpacked.finish();
                self.unpacked_digest = Some(value);
                value
            } else {
                fragment_digest.finish()
            };
            let mut scratch = std::mem::take(&mut self.header_scratch);
            self.member_header(
                index,
                fragment,
                field,
                self.stored_as(last, Some(digest)),
                &mut scratch,
            );
            // **Checked, not asserted.** `Run::streams_packed` is why the
            // corrected header is the same length as the one it replaces,
            // and a correction of another length would write over the
            // block after it instead of saying so. Header emission is not
            // a hot path at any member count this library serves (spec G
            // section 2), so this costs nothing worth having.
            let corrected = if scratch.bytes.len() == header_len {
                self.correct_header(header_at, &scratch.bytes)
            } else {
                Err(refuse(
                    "a streamed fragment's corrected header is a different length \
                     from the one it replaces",
                ))
            };
            self.header_scratch = scratch;
            corrected?;

            self.budget -= field.min(self.budget);
            packed_total = packed_total.saturating_add(placed);
            self.stream.placed = packed_total;
            first = false;
            if last {
                break;
            }
        }

        // What the next batch's estimate is built on (`Run::packed_seen`).
        self.packed_seen = self.packed_seen.saturating_add(packed_total);
        self.unpacked_seen = self.unpacked_seen.saturating_add(want);
        Ok(())
    }
}
