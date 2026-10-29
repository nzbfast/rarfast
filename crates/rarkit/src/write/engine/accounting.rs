//! The run's memory accounting: what its buffers hold now, what the lead
//! and each crew are charged, and the high-water mark it reports.

use super::*;

// How many times the packed buffer has been REALLOCATED by an encode on
// this thread. The withdrawn reserve existed to hold it at
// zero; it is kept because it is how that reserve was MEASURED, and
// how a successor will measure it again. This crate's own tests only;
// nothing in a shipped build carries it.
#[cfg(test)]
thread_local! {
    pub(super) static PACKED_GREW: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Starts the count in [`packed_grew`] again from zero.
#[cfg(test)]
pub(crate) fn forget_packed_growth() {
    PACKED_GREW.with(|count| count.set(0));
}

/// How many times an encode has grown [`Run::packed`] on this thread
/// since [`forget_packed_growth`].
#[cfg(test)]
pub(crate) fn packed_grew() -> usize {
    PACKED_GREW.with(std::cell::Cell::get)
}

/// Notes whether an encode reallocated the packed buffer.
///
/// The encoders append into the buffer, so there is no single call to
/// watch the way `Out::write` watches the recovery copy: what is
/// compared is the CAPACITY either side of the encode, which changes if
/// and only if the buffer was reallocated at least once.
pub(super) fn note_packed_capacity(_before: usize, _after: usize) {
    #[cfg(test)]
    if _after != _before {
        PACKED_GREW.with(|count| count.set(count.get() + 1));
    }
}

/// What the default's lead alone planned to hold, for the test's print.
pub(super) fn note_plan(bytes: u64) {
    #[cfg(feature = "bench-internals")]
    if std::env::var_os("RARKIT_RUNG_SAY").is_some() {
        eprintln!(
            "rarkit rung: the default's lead alone plans {} MiB",
            bytes >> 20
        );
    }
    #[cfg(not(feature = "bench-internals"))]
    let _ = bytes;
}

/// What the lead certainly needs, for the count's print.
pub(super) fn note_needed(bytes: u64) {
    #[cfg(feature = "bench-internals")]
    if std::env::var_os("RARKIT_RUNG_SAY").is_some() {
        eprintln!("rarkit rung: the lead certainly needs {} MiB", bytes >> 20);
    }
    #[cfg(not(feature = "bench-internals"))]
    let _ = bytes;
}

/// What the worker team's CHARGED memory stays inside where no caller
/// named a ceiling (`Run::team_width`, `Run::choose_large_lane`,
/// `Run::choose_lead_depth`): the policy's own `working_limit`, or in a
/// bench build `RARKIT_TEAM_DEFAULT_CEILING` bytes (`none` for no ceiling
/// at all; the figure is taken as given, the macOS term below not taken
/// off it), for the timed run that holds a machine with memory to the 512
/// MiB floor's figure.
///
/// Until 1 Oct 2026 this was the constant `MemoryPolicy::DEFAULT_LIMIT`
/// less a fixed 64 MiB for the process, whatever the policy. `rarfast`
/// builds its policy with `MemoryPolicy::process_default` (SPEC-API
/// 8.4.1), whose `working_limit` is the machine's default
/// process budget (the larger of 512 MiB and a quarter of physical memory)
/// already less the process headroom and the caller's resident bytes, so
/// the team is held to that and the process to the budget; a library
/// caller's `default()` is held to its engine limit, which is what
/// `from_limit` promises. Two counts on bin4g at `-m3`
/// (measured 30 Sep 2026): against the constant,
/// once its 237 MB member streamed, the team widened into
/// the old figure and the process peaked at 516 to 521 MiB at `-mt8` and
/// `-mt16`, and at 594 to 681 at 32 and 48 threads; and a scaled limit
/// with the team still on the constant ran SLOWER than the earlier code (0.94x, in the
/// census work), which is why nothing here reads the constant.
pub(super) fn team_ceiling(working_limit: u64) -> u64 {
    #[cfg(feature = "bench-internals")]
    if let Ok(value) = std::env::var("RARKIT_TEAM_DEFAULT_CEILING") {
        return match value.as_str() {
            "none" => u64::MAX,
            bytes => bytes.parse().unwrap_or(working_limit),
        };
    }
    working_limit.saturating_sub(TEAM_BESIDE_WRITER)
}

/// What the process holds beside the writer's live bytes where it is
/// judged on macOS's `phys_footprint`, which the team's room
/// at the default policy leaves beside the policy's own process headroom:
/// the allocator's per-thread regions and the blocks it keeps after a
/// free. A counted platform term (an Apple M3 Mac, macOS 27.0, bin4g at `-m3`,
/// 30 Sep 2026):
///
/// - the footprint ran 94 to 137 MiB above the writer's stated peak at 4
///   to 32 threads before the writer's batch went to 64 blocks, and 160
///   to 235 MiB after, against the 71 MiB `MemoryPolicy::process_default`
///   keeps back at 32 threads; `malloc_zone_pressure_relief` gave back
///   nothing;
/// - at 64 MiB here one floor row read 516 MiB; at 96 MiB, at the 512
///   MiB floor's exact figures, `-mt32` read 522, 508 and 503 MiB, one of
///   three over; at 128 MiB every rep is inside: 458 to 465 at `-mt32`,
///   454 to 466 at `-mt16`, 461 at `-mt8`. So it is 128.
///
/// It narrows only a machine whose default IS the floor (2 GiB
/// of memory or less); every other Mac's default budget is 2 GiB and more
/// and the team runs the pool's width. On Linux, with glibc holding blocks
/// of 1 MiB and more apart, the resident set ran 2 to 39 MiB
/// above the stated peak and the policy's headroom covers that. It was 64
/// MiB everywhere from 28 Sep 2026, when the team's room was a fixed 512
/// MiB less it.
#[cfg(target_os = "macos")]
pub(super) const TEAM_BESIDE_WRITER: u64 = 128 << 20;

#[cfg(not(target_os = "macos"))]
pub(super) const TEAM_BESIDE_WRITER: u64 = 0;

/// What one crew's encoder is ALLOWED for a `Payload::Bytes` member, for
/// `Run::team_width`'s share of the memory policy. An allowance, from spec
/// H3 section 8.3's figures for a member of at most [`TEAM_MEMBER_MOST`]:
/// the chains' 4 MiB of heads and their links, or the tree's 8 MiB of
/// slots, its heads and one block's hints, and a parse's scratch. A crew
/// that encodes READER members is charged more where its finder is larger
/// (`Run::crew_bytes`).
pub(super) const CREW_BYTES: u64 = 16 << 20;

/// What a caller's ceiling keeps back, when the lead's parses are held
/// (`Run::chosen_parses`), for what the PROCESS holds beside the writer's
/// working memory: its code as it is paged in, its threads' stacks, the
/// allocator's own books and the caller's sink. Measured 28 Sep 2026 at
/// -m4 and -m5 with `create_rivals --to-disk`: RSS 1 to 4 MiB above the
/// live heap, and the heap up to 4 MiB above what the writer states (the
/// sink's own 1 MiB buffer among it).
pub(super) const PROCESS_ROOM_BYTES: u64 = 8 << 20;

/// The most a caller's NAMED ceiling charges for the lead's parses in
/// flight (`Run::named_most_bytes`, FROM-STUDIO 840): the largest held
/// figure counted, and a quarter more. `Encoder::flight_term` charges a
/// full scratch for every thread the wave could take, 68 to 100 MiB at
/// `-m5` at 18 threads; what the parses held was 10 to 19 MiB on single
/// text members and solid text and 45 MiB on one 2 GiB member at `-md32m`
/// and at `-md128m -s` (counted 25 Oct 2026, macOS, M5 Max, 18 threads,
/// `RARKIT_TEAM_SAY`'s peak terms).
pub(super) const NAMED_FLIGHT_MOST: u64 = 56 << 20;

/// The most kept judges a caller's NAMED ceiling charges at once
/// (`Run::judges_most`, FROM-STUDIO 840): the most held at once counted,
/// five over one 2 GiB member at `-md128m -s` (one or two on every other
/// row), and one more (counted as [`NAMED_FLIGHT_MOST`] was).
pub(super) const NAMED_JUDGES_MOST: usize = 6;

#[cfg(feature = "bench-internals")]
thread_local! {
    /// What the run held at its last new high-water mark, by term, for
    /// the count's print (`RARKIT_TEAM_SAY`).
    pub(super) static PEAK_SAID: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Whether `RARKIT_TEAM_SAY` is set, read ONCE a process. `note_peak`
/// asks at every member and every megabyte copied, and a read of the
/// environment is not free everywhere: on Windows the standard library
/// widens the name into a buffer of its own before it asks, which is one
/// allocation a call. Counted on a hosted Windows runner on 6 Oct 2026
/// with `tests/write_allocation.rs`: 1,019 allocations over 1,000 stored
/// members and 2,019 over 2,000, where Linux and macOS made 16 and 16.
/// A bench build only, so no shipped binary ever made them; a bench arm
/// on Windows did.
#[cfg(feature = "bench-internals")]
fn team_say() -> bool {
    static SAY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SAY.get_or_init(|| std::env::var_os("RARKIT_TEAM_SAY").is_some())
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// What this run's buffers hold BETWEEN THEM at this instant, in
    /// bytes TOUCHED.
    ///
    /// Every term is a length and not a capacity, and that is the one
    /// rule. A buffer's untouched reserve costs ADDRESS SPACE and
    /// not memory, because a page that is never written is never
    /// resident, so counting it would report memory a caller does not
    /// pay for - and would make this figure rise when a buffer is
    /// reserved to a bound instead of grown to it, which is precisely
    /// the trade that was settled (`Run::packed_reserve_bytes`).
    ///
    /// `Encoder::held_bytes` and `Out::kept` are already in-use figures.
    /// `Run::buffer` is `vec![0u8; COPY_CHUNK]`, wholly touched, so its
    /// length and its capacity are the same number. Three terms are
    /// buffers kept EMPTY and so are counted at what they were grown to,
    /// which was touched: the encoders' parses (`Encoder::flight_bytes`:
    /// their scratches, kept block outputs and walkers' bins), the team's
    /// kept buffers (`Run::keep_spare`) and the member table. All three
    /// were unstated before 28 Sep 2026, when tree5k at -m5 -mm96 held
    /// about 33 MiB of live heap beyond this figure. The store rule's
    /// judges are stated at the most there have been at once, each at its
    /// whole tables (`store::Judges::held_bytes`): 2 MiB a judge, at most
    /// eight kept, none where the caller named a ceiling.
    pub(super) fn working_now(&self) -> u64 {
        let buffers = self
            .buffer
            .len()
            .saturating_add(self.scratch.len())
            .saturating_add(if self.packed_held {
                self.packed.len().max(self.held_touched)
            } else {
                self.packed.len()
            })
            .saturating_add(if self.held_spare.capacity() > 0 {
                self.held_touched
            } else {
                0
            })
            .saturating_add(self.stream.pending.len())
            .saturating_add(self.ahead.iter().map(Vec::len).sum::<usize>())
            .saturating_add(self.prefetch_buf.len())
            .saturating_add(self.ahead_input.len())
            .saturating_add(self.restage_buf.len())
            .saturating_add(self.cipher_out.len())
            .saturating_add(self.ahead_pool.iter().map(Vec::len).sum::<usize>())
            .saturating_add(self.prefix.held())
            .saturating_add(
                self.pulled_ahead
                    .as_ref()
                    .map_or(0, |(_, bytes)| bytes.len()),
            )
            .saturating_add(
                self.head_ahead
                    .as_ref()
                    .map_or(0, |(_, head, _)| head.held()),
            ) as u64;
        let team = self.team_now();
        // The run's own encoder: its carried history, its finder and
        // hints, which are written whole when built and so are resident,
        // and its parses' scratches, kept block outputs and walkers' bins
        // (SPEC-API 8.2's parse wave and tree walk rows).
        let encoder = self.encoder.as_ref().map_or(0, |encoder| {
            encoder
                .held_bytes()
                .saturating_add(encoder.structure_bytes())
                .saturating_add(encoder.flight_bytes())
        });
        buffers
            .saturating_add(encoder)
            .saturating_add(self.judges.held_bytes())
            .saturating_add(self.segments.held())
            .saturating_add(self.member_table_bytes())
            .saturating_add(self.header_scratch.held())
            .saturating_add(self.out.kept().len() as u64)
            .saturating_add(self.recovery_scratch)
            .saturating_add(team)
            .saturating_add(self.chains_held())
    }

    /// What the worker team holds now, of [`Run::working_now`]: the batch
    /// waiting to be written, the crews' structures between rounds, and
    /// the buffers kept for the next batch.
    pub(super) fn team_now(&self) -> u64 {
        self.team_ready
            .iter()
            .flatten()
            .filter_map(|prepared| prepared.as_ref().ok())
            .map(|prepared| prepared.packed.capacity() as u64)
            .sum::<u64>()
            .saturating_add(self.team_held)
            .saturating_add(self.team_resident)
            .saturating_add(self.team_spare_bytes())
            .saturating_add(
                self.team_pulls
                    .iter()
                    .map(|buffer| buffer.len() as u64)
                    .sum::<u64>(),
            )
            .saturating_add(
                self.packed_pool
                    .iter()
                    .map(|buffer| buffer.capacity() as u64)
                    .sum::<u64>(),
            )
    }

    /// The member table's own bytes: one [`Planned`] a member, which the
    /// writer holds for the whole run (spec G 7.3 allows it; the names and
    /// payloads are the caller's and are borrowed). Stated since 28 Sep
    /// 2026: for small9k's 9,682 members it is about 4 MiB, which a
    /// caller's budget pays like any other buffer.
    pub(super) fn member_table_bytes(&self) -> u64 {
        (self.members.capacity() * std::mem::size_of::<Planned<'_>>()) as u64
    }

    /// Sample [`Run::working_now`] into the run's high-water mark.
    ///
    /// **Where this is called from is the whole correctness argument**,
    /// because the maximum of a SUM is not the sum of the maxima: the
    /// sampling instants have to include the one the true maximum falls
    /// at. They do, and the reason is that each buffer grows
    /// MONOTONICALLY across the span it is used over and is cleared
    /// between spans, so the total is at a local maximum exactly at the
    /// end of each span. The calls are at those ends: after a member's
    /// packed bytes are complete (`Run::compress`, and each window of
    /// `Run::compress_streaming`), after a batch fills `ahead`
    /// (`Run::batch_solid`), after a chunk of a streamed member is
    /// produced (`Run::stream_pull`), after a header image is built
    /// (`Run::write_header_and_cache`), after a chunk is enciphered
    /// (`Run::copy_payload`), and at each volume boundary while the
    /// recovery copy is still held (`Run::next_volume`,
    /// `Run::close_volume`). `Run::report` samples once more, so a run
    /// that reaches none of them still answers honestly.
    ///
    /// It is a dozen field reads and a walk of `ahead`, whose length is
    /// `batch_depth` at most. None of the sites above is in an inner
    /// copy loop: the tightest of them runs once per `COPY_CHUNK`, which
    /// is a megabyte (`write::options::COPY_CHUNK`), so the cost does
    /// not reach the wall, which comes first.
    pub(super) fn note_peak(&mut self) {
        #[cfg(feature = "bench-internals")]
        if team_say() {
            let now = self.working_now();
            if now > self.peak + (1 << 20) {
                let encoder = self.encoder.as_ref().map_or((0, 0, 0), |encoder| {
                    (
                        encoder.held_bytes() >> 20,
                        encoder.structure_bytes() >> 20,
                        encoder.flight_bytes() >> 20,
                    )
                });
                PEAK_SAID.with(|said| {
                    *said.borrow_mut() = format!(
                        "peak {} MiB: buffer {} scratch {} packed {} (touched {}) pending {} ahead {} ahead_input {} encoder held/structure/flight {}/{}/{} segments {} team {} judges {} kept_out {} table {}",
                        now >> 20,
                        self.buffer.len() >> 20,
                        self.scratch.len() >> 20,
                        self.packed.len() >> 20,
                        self.held_touched >> 20,
                        self.stream.pending.len() >> 20,
                        self.ahead.iter().map(Vec::len).sum::<usize>() >> 20,
                        self.ahead_input.len() >> 20,
                        encoder.0,
                        encoder.1,
                        encoder.2,
                        self.segments.held() >> 20,
                        self.team_now() >> 20,
                        self.judges.held_bytes() >> 20,
                        self.out.kept().len() >> 20,
                        self.member_table_bytes() >> 20,
                    );
                });
            }
        }
        self.peak = self.peak.max(self.working_now());
    }

    /// What one crew of a team WITHOUT a caller's ceiling is charged, in
    /// bytes, for `Run::team_width`'s share of the default policy's
    /// `working_limit`. Each term is what the crew really holds, not an
    /// allowance:
    ///
    /// - its encoder's finder, hints and carried history for the LARGEST
    ///   member the team takes (`Encoder::member_structure_bytes`): a crew's
    ///   structures only grow inside a run, so they are that member's once
    ///   it has encoded it. A READER member of one window is a run of its
    ///   own (`pack_member`), its tree sized from the history as
    ///   [`Run::crew_bytes`] says, its chains from the member, and the
    ///   chunk held as its history; a longer one is the windowed encode's
    ///   (`Encoder::member_held_bytes`);
    /// - that member's parses in flight, one block's tokens (eight bytes a
    ///   position) and output (half a block at most) for each of its
    ///   blocks;
    /// - its share of the three batches `Run::beside_team_bytes` counts,
    ///   two packed and one pulled, which grow by [`CREW_BATCH_BYTES`] and
    ///   [`CREW_BATCH_MEMBERS`] stored blocks' room a crew
    ///   (`Run::team_batch`).
    pub(super) fn crew_charge(&self) -> u64 {
        self.crew_charge_upto(self.team_most, None)
    }

    /// [`Run::crew_charge`] for a crew whose members are at most `most`
    /// bytes, its encoder held to `hold` bytes in flight where given: the
    /// small crews' at `Run::team_most`, the large-member lane's at
    /// `Run::large_most` held to [`LARGE_CREW_HOLD`].
    pub(super) fn crew_charge_upto(&self, most: u64, hold: Option<usize>) -> u64 {
        let taken = (0..self.members.len())
            .filter(|&index| self.team_takes(index) && self.members[index].size <= most);
        let (readers, largest) = taken.fold((false, 0u64), |(readers, largest), index| {
            let member = &self.members[index];
            (
                readers || matches!(member.payload, Payload::Reader { .. }),
                largest.max(member.size),
            )
        });
        let len = usize::try_from(largest.max(1)).unwrap_or(usize::MAX);
        let block = crate::encode::drive::PARSE_BLOCK_BYTES as u64;
        // The member's blocks in flight at once: all of them, or the held
        // wave's where the finder keeps it. The tree's hints do; a crew's
        // chains, sized from a member shorter than their held ceiling,
        // never wrap and parse every block of it at once, held or not
        // (`Engine::flight_term_over`).
        let tree = self.new_encoder().walks_tree();
        let blocks = (largest.max(1)).div_ceil(block).min(
            hold.filter(|_| tree)
                .map_or(u64::MAX, |hold| (hold as u64 / block).max(1)),
        );
        let batch = CREW_BATCH_BYTES + CREW_BATCH_MEMBERS as u64 * STORED_BLOCK_ROOM;
        let window = self.window_bytes();
        let mut probe = match hold {
            Some(hold) => self.encoder_held(Some(hold)),
            None => self.new_encoder(),
        };
        // A reader past one window (the lane's reach) is the windowed
        // encode's under the walk's slack, a staged flush at a time over
        // chains that wrap: its parses in flight are the engine's own
        // figure for that flush, as the lead's are (`Run::alone_bytes`),
        // and not every block of the member.
        let past = readers && len > window;
        if past {
            probe.set_slack_multiple(self.streamed_slack_multiple());
        }
        let flight = if past {
            let flush = self.lead_window_flush().min(len);
            let span = usize::try_from(self.dictionary)
                .unwrap_or(usize::MAX)
                .saturating_add(flush);
            probe.flight_term_over(flush, span)
        } else {
            blocks.saturating_mul(block * 8 + block / 2)
        };
        // A reader of one window is a run of its own in one chunk
        // (`pack_member`), which holds the chunk as its history; a longer
        // one is the windowed encode's.
        let finder = match (readers, len <= window) {
            (false, _) => probe.member_structure_bytes(len, false),
            (true, true) => probe
                .member_structure_bytes(len, true)
                .saturating_add(len as u64),
            (true, false) => probe.member_held_bytes(len, Some(window)),
        };
        // Where a lone member is walked by another finder (levels 4 and
        // 5), a crew that takes both lone and longer members
        // holds both: the chains for one block beside the tree.
        let lone_beside = if probe.lone_finder_differs() && largest > TEAM_MEMBER_MOST {
            probe.member_structure_bytes(crate::encode::drive::PARSE_BLOCK_BYTES, readers)
        } else {
            0
        };
        let finder = finder.saturating_add(lone_beside);
        finder.saturating_add(flight).saturating_add(3 * batch)
    }

    /// What one crew of the worker team holds, in bytes, for a caller's
    /// ceiling (`Run::team_width`, `Run::chosen_hold`): what its encoder
    /// builds for a member of at most [`TEAM_MEMBER_MOST`], computed from
    /// the encoder's own sizing for the largest member it takes, and never
    /// less than [`CREW_BYTES`].
    ///
    /// Three terms. The FINDER: a reader member is the windowed encode's
    /// run (`pack_member`), whose tree is sized from the run's DICTIONARY
    /// and not from the member (at levels 4 and 5 and a 2 MiB dictionary
    /// 20 MiB of tree and 4 MiB of hints, where a member of one parse
    /// block encoded from its slice builds 10 MiB of tree), so ONE large
    /// member lifts every crew's finder; before that was charged a set of
    /// 9,681 small members and one of 20 MiB at `-m5 -mt8` peaked at 301
    /// MiB of RSS against about 140 MiB charged. Its PARSE: one block's
    /// scratch and output, and at the tree's levels the walkers' bins,
    /// since a block is walked wide (`Encoder::flight_term`); both of a
    /// member's size at most. Its HISTORY: the member. Before 28 Sep 2026
    /// the charge was [`CREW_BYTES`] plus the finder's excess alone, and
    /// tree5k at -m5 -mm256 ran five crews that held about 3.5 MiB each
    /// more than they were charged.
    ///
    /// A function of the options and the member table, so the width is
    /// the same on every run of the same inputs.
    pub(super) fn crew_bytes(&self) -> u64 {
        let taken = (0..self.members.len()).filter(|&index| self.team_takes(index));
        let readers = taken
            .clone()
            .any(|index| matches!(self.members[index].payload, Payload::Reader { .. }));
        // The largest member the team takes: a crew's tokens, output and
        // history never pass it (`Encoder::flight_term`).
        let largest = taken
            .map(|index| self.members[index].size)
            .max()
            .unwrap_or(TEAM_MEMBER_MOST);
        let probe = self.new_encoder();
        let own = probe
            .one_block_structure_bytes(readers)
            .saturating_add(probe.flight_term(largest as usize))
            .saturating_add(largest);
        CREW_BYTES.max(own)
    }

    /// What the run holds BESIDE the worker team at its most, in bytes,
    /// for `Run::team_width`'s share of a caller's ceiling. Stated as its
    /// terms, each an upper bound:
    ///
    /// - the LEAD encoder's finder, hints and carried history
    ///   (`Encoder::member_held_bytes`) and the member's packed output,
    ///   for the member the team does not take that asks most of them:
    ///   the writing thread encodes it while the crews run;
    /// - a reader member's window, which it is read through, and under a
    ///   caller's ceiling the head the store rule's samples hold of it
    ///   (`Run::sampled_head_bytes`);
    /// - the lead encoder's parses in flight for that member's flush
    ///   (`Encoder::flight_term`): a scratch per block parsed at once,
    ///   which is its wave's width held to the pool's (a block's tokens at
    ///   eight bytes a position, the optimal parse's window), each block
    ///   of the wave's output, and the tree walkers' bins; at least one
    ///   block's, since a member the team would take is the lead's when
    ///   no team runs. The report states them too (`Run::working_now`),
    ///   and a hold narrows the wave, so they follow the hold. Counted 28
    ///   Sep 2026 at a flat two and a quarter MiB a thread, tree5k at -m5
    ///   -mm96 held about 33 MiB of live heap nobody stated;
    /// - two team batches' packed output and one batch's pulled input
    ///   (`Run::walk_team`), and the buffers the team keeps between them
    ///   ([`TEAM_SPARE_BYTES`], `Run::keep_spare`), and the packed
    ///   buffers it keeps at their floor ([`PACKED_POOL_BYTES`]);
    /// - the copy buffer every payload passes through, and the member
    ///   table (`Run::alone_bytes`).
    ///
    /// A function of the options, the member table and `hold`, the lead's
    /// hold (`Run::chosen_hold`), as the width is.
    pub(super) fn beside_team_bytes(&self, hold: Option<usize>) -> u64 {
        self.alone_bytes(hold, self.parses)
            .saturating_add(self.team_terms_bytes())
    }

    /// The terms [`Run::beside_team_bytes`] adds to the lead's for the
    /// team's sake: two batches' packed output and one's pulled input, the
    /// buffers it keeps between batches, and the packed buffers it keeps at
    /// their floor.
    pub(super) fn team_terms_bytes(&self) -> u64 {
        let batch = TEAM_BATCH_BYTES + TEAM_BATCH_MOST as u64 * STORED_BLOCK_ROOM;
        // The packed buffers the team keeps for the next batch
        // (`Run::lend_packed`), at their floor, where no caller named a
        // ceiling: 15 MiB of them were held, uncharged, at bin4g's peak at
        // `-m3`.
        // Past the floor they follow the batch, which each crew's share
        // already charges (`Run::crew_charge_upto`). A caller's ceiling
        // keeps the sum it was measured with, as its `-mm` is not changed yet
        // (SPEC-API 8.4.1's `for_process`).
        let pool = if self.dial_ceiling().is_none() {
            PACKED_POOL_BYTES as u64
        } else {
            0
        };
        (3 * batch)
            .saturating_add(TEAM_SPARE_BYTES)
            .saturating_add(pool)
    }

    /// What the run holds at its most with no worker team: the lead's
    /// terms of [`Run::beside_team_bytes`], the copy buffer and the member
    /// table, with the lead held to `hold` and its parses to `parses`.
    pub(super) fn alone_bytes(&self, hold: Option<usize>, parses: Option<usize>) -> u64 {
        self.lead_bytes(hold, parses, false)
    }

    /// The ONE member the lead encodes, where it encodes one: what
    /// [`Run::lead_bytes`] charges one finder for and whose head
    /// [`Run::read_lone_head`] reads. Asked before the team's members are
    /// chosen, the lead's count errs high, so one member here is one
    /// member when it runs.
    pub(super) fn lone_lead(&self) -> Option<usize> {
        let mut leads = (0..self.members.len()).filter(|&index| {
            let member = &self.members[index];
            !member.is_directory && member.size > 0 && !self.team_takes(index)
        });
        let first = leads.next()?;
        leads.next().is_none().then_some(first)
    }

    /// The head member `index`'s class is read from, as the encode will
    /// read it (`Run::start_member_run`), where the writer has it: nothing
    /// to read for a member under a megabyte or a level that reads no
    /// class; bytes in memory, their own; a reader, the head
    /// [`Run::read_lone_head`] pulled and holds. `None` where it has no
    /// head, and the member is charged the larger finder.
    fn lone_head(&self, index: usize) -> Option<&[u8]> {
        let member = &self.members[index];
        if !self.reads_class() || member.size < class::HEAD_BYTES as u64 {
            return Some(&[]);
        }
        match &member.payload {
            Payload::Bytes(data) => Some(data),
            Payload::Reader { .. } => self.prefix.held_head(index, class::HEAD_BYTES),
        }
    }

    /// [`Run::alone_bytes`], or with `named` what a caller's NAMED ceiling
    /// charges for the same terms (`Run::named_most_bytes`, FROM-STUDIO
    /// 840): ONE finder where the lead encodes one member, since an engine
    /// builds the finder its member's class calls for and no other
    /// (`Encoder::member_named_finder_bytes`), and the parses in flight
    /// held to [`NAMED_FLIGHT_MOST`].
    fn lead_bytes(&self, hold: Option<usize>, parses: Option<usize>, named: bool) -> u64 {
        let probe = self.encoder_capped(hold, parses);
        // A member above one window runs its history to the streamed
        // slack (`Run::streamed_slack_multiple`), eight dictionaries where
        // the probe's own is four: charged at four until 1 Oct 2026, a
        // windowed member held 8 MiB of history at a 2 MiB dictionary that
        // no sum counted (stated 72 MiB against 67 charged under a 96 MiB
        // figure).
        let mut slid = self.encoder_capped(hold, parses);
        slid.set_slack_multiple(self.streamed_slack_multiple());
        let window = self.window_bytes();
        let leads = |&index: &usize| {
            let member = &self.members[index];
            !member.is_directory && member.size > 0 && !self.team_takes(index)
        };
        let one = named && self.lone_lead().is_some();
        let flight = |bytes: u64| {
            if named {
                bytes.min(NAMED_FLIGHT_MOST)
            } else {
                bytes
            }
        };
        let lead = (0..self.members.len())
            .filter(leads)
            .map(|index| {
                let member = &self.members[index];
                let len = usize::try_from(member.size).unwrap_or(usize::MAX);
                let reader = matches!(member.payload, Payload::Reader { .. });
                let streams = self.streams_packed(index);
                let windowed = (reader || streams).then_some(window);
                // A windowed member's flush is a staged batch of its
                // windows (`Run::lead_window_flush`), and its packed bytes
                // are that batch's where it streams. Held, they are one
                // buffer: a reader longer than a window is reserved its
                // bound and appended to (`Run::held_kept`), and anything
                // else is one region's or one window's buffer swapped in.
                let flush = windowed.map_or(len, |_| self.lead_window_flush().min(len));
                let packed = if streams {
                    flush as u64
                } else {
                    self.packed_bound(index)
                };
                // Read ahead of its one engine (`WindowsAhead`), it is read
                // through two windows (`Run::ahead_bytes`).
                let read = if windowed.is_some() && len > window && self.windows_ahead() {
                    self.ahead_bytes().min(len) as u64
                } else if reader {
                    window as u64
                } else {
                    0
                };
                // A reader sampled for the store rule keeps the head it
                // pulled for the vote until the encode reads it back
                // (`store::Prefix`). Under a caller's ceiling that is
                // `Run::sampled_head_bytes`, below; where no ceiling was
                // named it is the same head (`Run::sampled_head`), charged
                // here so the default's admission counts it too. Its
                // buffer may be reserved past that, but only what was read
                // into it is resident. Exactly one of the two is non-zero.
                let prefix = if self.caller_ceiling().is_none() {
                    self.sampled_head(index)
                } else {
                    0
                };
                // The chains wrap over the history and the flush, not the
                // flush alone (`Engine::flight_term_over`).
                let span = windowed.map_or(len, |_| {
                    usize::try_from(self.dictionary)
                        .unwrap_or(usize::MAX)
                        .saturating_add(flush)
                });
                let held = if windowed.is_some() && len > window {
                    &slid
                } else {
                    &probe
                };
                let finders = if one {
                    held.member_named_finder_bytes(len, windowed, self.lone_head(index))
                } else {
                    held.member_held_bytes(len, windowed)
                };
                finders
                    .saturating_add(flight(probe.flight_term_over(flush, span)))
                    .saturating_add(packed)
                    .saturating_add(read)
                    .saturating_add(self.sampled_head_bytes(index))
                    .saturating_add(prefix)
            })
            .max()
            .unwrap_or(0)
            .max(flight(probe.flight_term(TEAM_MEMBER_MOST as usize)));
        lead.saturating_add(COPY_CHUNK as u64)
            .saturating_add(self.member_table_bytes())
    }

    /// What the run's own encoder CERTAINLY holds for the member that asks
    /// most of it, at `hold` and `parses`: its finder, its hints and its
    /// carried history (`Encoder::member_held_bytes`), which are written
    /// whole when built and so are resident, and nothing else of
    /// [`Run::alone_bytes`].
    ///
    /// It is a LOWER bound of what the process will hold, where
    /// `alone_bytes` is a plan: counted 2 Oct 2026 under real cgroup
    /// limits,
    /// that sum planned 120 MiB for one 64 MiB member at level 1 on
    /// sixteen threads where the write stated 85 and completed under 128
    /// MiB (its parses in flight are charged a full scratch a thread), and
    /// it does not see a solid run's chains at all. So the refusal
    /// (`Run::choose_rung`) weighs this figure and catches only what
    /// cannot run by any plan: a dictionary and its finder the cap cannot
    /// hold.
    pub(super) fn lead_certain_bytes(&self, hold: Option<usize>, parses: Option<usize>) -> u64 {
        self.lead_held_by(hold, parses, Encoder::member_held_bytes)
    }

    /// The most the run can hold under a ceiling the caller NAMED, the
    /// figure [`Run::refuse_over_named_ceiling`] weighs: every term
    /// [`Run::working_now`] states, each at the most it can reach for this
    /// member table at the hold and parses the run already chose.
    ///
    /// - A run that is not solid: the lead's plan alone
    ///   ([`Run::lead_bytes`]'s named charge: the history, the parses in
    ///   flight held to [`NAMED_FLIGHT_MOST`], the packed and read buffers,
    ///   the sampled head, the copy buffer and the member table, and both
    ///   level 5 finders where the lead's members can call both classes,
    ///   which over many members are built and live at once, but ONE for a
    ///   lead of one member, the finder its class builds). On the default's
    ///   plan the team's own terms ([`Run::team_terms_bytes`]) where a team
    ///   may run ([`Run::team_may_run`]), and nothing for them where none
    ///   can; on the small path's dials ([`Run::dial_ceiling`]) the team is
    ///   fitted to the ceiling by its own chooser (`Run::team_width`'s
    ///   share), as it was.
    /// - A SOLID run: [`Run::solid_most_bytes`], the stream's history.
    /// - Both: the store rule's kept judges ([`Run::judges_most`]).
    ///
    /// Each term is charged at what is held since 25 Oct 2026: counted
    /// that day on macOS at `-m5 -md32m` and the shipped width, 34 MiB of text
    /// held the chains and 34 MiB of prose the tree, never both, where
    /// both had been charged; no team ran beside one member, where its
    /// terms (37 MiB) had been charged; the parses and the judges as their
    /// bounds say.
    pub(super) fn named_most_bytes(&self) -> u64 {
        let lead = if self.options.solid {
            self.solid_most_bytes(self.hold, self.parses)
        } else if self.dial_ceiling().is_some() || !self.team_may_run() {
            self.lead_bytes(self.hold, self.parses, true)
        } else {
            self.lead_bytes(self.hold, self.parses, true)
                .saturating_add(self.team_terms_bytes())
        };
        lead.saturating_add(self.judges_most())
    }

    /// The most the store rule's KEPT judges hold at once
    /// (`store::Judges`): none on the small path's dials, where every
    /// sample is packed one at a time by a judge built for it and dropped
    /// before the member is encoded (`Run::samples_store`, the reader's
    /// `store::Prefix::sample`); elsewhere one a vote taken at once, at most
    /// one a thread of the run's width and at most what one vote's round
    /// packs at once (`store::JUDGES_AT_ONCE`). Counted 25 Oct 2026 on
    /// macOS at 18 threads: five over one 2 GiB member, one or two over
    /// 11,753 solid text files.
    pub(super) fn judges_most(&self) -> u64 {
        if self.dial_ceiling().is_some() {
            return 0;
        }
        let width = super::width::pool_width().min(self.options.encoder_width());
        // The most counted at once and one more (`NAMED_JUDGES_MOST`).
        self.judges
            .most_bytes(width.min(store::JUDGES_AT_ONCE).min(NAMED_JUDGES_MOST))
    }

    /// What a SOLID run's lead holds at its most: the stream's history,
    /// not one member's, with ONE finder over it
    /// (`Encoder::member_named_finder_bytes` over every byte the encoder
    /// reads, up to a window at the streamed slack), the parses of one
    /// flush held to [`NAMED_FLIGHT_MOST`], the copy buffer and the member
    /// table.
    ///
    /// One finder, because a solid run built one: counted 25 Oct 2026 at
    /// `-m5 -md128m -s` over 118 MB of text and over one 2 GiB member, its
    /// structures stayed at the one finder's 1,028 MiB to the end, where
    /// the per-member sum's two finders charge 1,689 and 1,892. The worker
    /// team and the read buffers the run also held (16 and up to 18 MiB on
    /// the text) are not summed here; the judges' term and the process's
    /// room cover them on every shape counted (the chain 40 admission
    /// counts).
    pub(super) fn solid_most_bytes(&self, hold: Option<usize>, parses: Option<usize>) -> u64 {
        let stream = (0..self.members.len())
            .filter(|&index| {
                let member = &self.members[index];
                !member.is_directory && member.size > 0 && !self.member_stored(index)
            })
            .fold(0_u64, |sum, index| {
                sum.saturating_add(self.members[index].size)
            });
        let len = usize::try_from(stream).unwrap_or(usize::MAX);
        let window = self.window_bytes();
        let mut held = self.encoder_capped(hold, parses);
        if len > window {
            held.set_slack_multiple(self.streamed_slack_multiple());
        }
        let flush = self.lead_window_flush().min(len);
        let span = usize::try_from(self.dictionary)
            .unwrap_or(usize::MAX)
            .saturating_add(flush);
        held.member_named_finder_bytes(len, Some(window), None)
            .saturating_add(held.flight_term_over(flush, span).min(NAMED_FLIGHT_MOST))
            .saturating_add(COPY_CHUNK as u64)
            .saturating_add(self.member_table_bytes())
    }

    /// [`Run::lead_certain_bytes`] with ONE finder charged where a
    /// member's class decides between two (`Encoder::member_one_finder_bytes`):
    /// what the REFUSAL weighs (`Run::choose_rung`'s rung 3).
    ///
    /// At level 5 the class is read from the member's head
    /// (`Plan::for_member_on`), which no reader has given up when the rung
    /// is chosen, so the sum above charges the tree and the chains both;
    /// the run builds the one its member's class takes. Weighed whole, the
    /// refusal turned away a create that completes: counted 3 Oct 2026
    /// (x86-64, `MemoryMax`), `-m5
    /// -md32m` was refused under every cap from 512 to 607 MiB as needing
    /// 688 MiB, where under 608 MiB, and under 512 MiB with `-mm512m`, it
    /// wrote the default's bytes at 472 to 486 MiB of process. Charged the
    /// larger finder it is 428 MiB there.
    ///
    /// The hold's own question (`Run::chosen_hold`) keeps the sum above:
    /// which hold a run takes where nothing fits is not moved by this.
    pub(super) fn lead_one_finder_bytes(&self, hold: Option<usize>, parses: Option<usize>) -> u64 {
        self.lead_held_by(hold, parses, Encoder::member_one_finder_bytes)
    }

    /// The most `held` gives any member the run's own encoder compresses,
    /// at `hold` and `parses`: a windowed member above one window at the
    /// streamed slack, every other at the encoder's own.
    pub(super) fn lead_held_by(
        &self,
        hold: Option<usize>,
        parses: Option<usize>,
        held_bytes: fn(&Encoder, usize, Option<usize>) -> u64,
    ) -> u64 {
        let probe = self.encoder_capped(hold, parses);
        let mut slid = self.encoder_capped(hold, parses);
        slid.set_slack_multiple(self.streamed_slack_multiple());
        let window = self.window_bytes();
        (0..self.members.len())
            .filter(|&index| {
                let member = &self.members[index];
                !member.is_directory && member.size > 0 && !self.member_stored(index)
            })
            .map(|index| {
                let member = &self.members[index];
                let len = usize::try_from(member.size).unwrap_or(usize::MAX);
                let reader = matches!(member.payload, Payload::Reader { .. });
                let windowed =
                    (self.options.solid || reader || self.streams_packed(index)).then_some(window);
                let held = if windowed.is_some() && len > window {
                    &slid
                } else {
                    &probe
                };
                held_bytes(held, len, windowed)
            })
            .max()
            .unwrap_or(0)
    }

    /// The sampled head member `index` holds beside the lead's terms, for
    /// a CALLER'S ceiling (spec G 3.5, "the held sampled head";
    /// decided 1 Oct 2026 that the budget
    /// counts it): a READER member the store rule samples is pulled as
    /// far as the vote needs and held until the verdict, beside the
    /// lead's finder, and is then read back by the walk a piece at a time
    /// (`store::Prefix`).
    ///
    /// The term is the COMMON-CASE head, that of a member whose opening
    /// compresses, which is the member the lead's other terms are for:
    /// the vote is settled by the first sample past the misses the rule
    /// allows: for a member of 128 MiB and more the fifth of sixteen, 9/32
    /// of the span and half a sample (9 MiB + 32 KiB); for a smaller one,
    /// and under `WriteOptions::store_one_miss`, the second, 3/32. Until this was
    /// counted the hold was chosen as if the head cost nothing: with four
    /// misses allowed an 8 MiB member at `-md128k` stood 0.95 MiB over a
    /// ceiling of the walk's terms and the old head, and over again by
    /// 0.66 MiB at a ceiling raised by the new head, the chooser having
    /// spent the rise on a wider hold.
    ///
    /// It is not a bound. A member whose samples compress LATE in the
    /// span is compressed on a head of up to the whole span (spec G 3.5's
    /// bound is `min(U, 32 MiB)`), and may pass the ceiling by the
    /// difference: reported through `WriteReport::ceiling_exceeded_by`,
    /// never refused. A member the samples STORE is pulled to
    /// its last sample and then takes none of the lead's terms.
    ///
    /// Zero where the caller named no ceiling: the default policy's
    /// widths are what they were. A function of the options and the
    /// member table.
    pub(super) fn sampled_head_bytes(&self, index: usize) -> u64 {
        if self.caller_ceiling().is_none() {
            return 0;
        }
        self.sampled_head(index)
    }

    /// [`Run::lead_certain_bytes`] where the chains walk the member
    /// (`Encoder::member_chain_bytes`): what `Run::parses_under_cap` sizes
    /// the chains' wave from.
    pub(super) fn lead_chain_bytes(&self, hold: Option<usize>, parses: Option<usize>) -> u64 {
        self.lead_held_by(hold, parses, Encoder::member_chain_bytes)
    }
}
