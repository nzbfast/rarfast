//! The run itself: the engine driven over the plan, and how a walk that
//! ends early is said.

use super::*;

impl Run<'_> {
    pub(super) fn execute(
        &mut self,
        password: Option<&[u8]>,
        missing_volume: Option<String>,
    ) -> Exit {
        // An archive whose header walk stopped short - cut, or at a header
        // it cannot step over - is reported ONCE, after the members in
        // front of the damage, which are tested and extracted as in a
        // sound archive (spec F 4.6). See `UNEXPECTED_END` for the one
        // case where the reference says it twice and why this does not.
        //
        // A `t` or `x` carrying a MASK over a cut archive prints one or two
        // more at the reference, because it also counts each data area it
        // fails to seek past on its way to a member it was asked for. That
        // is bookkeeping inside its own walk rather than a property of the
        // archive, and it is not reproduced here.
        if self.selected.is_empty() && self.tail == Some(Tail::CorruptHeader) {
            // An enciphered header with no password check that failed before
            // any member was read: a wrong password, or damage. The
            // reference prints no banner, its sentence, and `No files to
            // extract` (which `-idd` keeps), exit 3 (rar 4.20 `-hp`
            // archives, `t`, `x` and `p`, right and wrong passwords; see
            // `Out::refused` for the layout).
            if let Some(text) = self.unchecked_header_text() {
                self.streams
                    .refused(&format!("\n{text}"), Some("No files to extract\n"));
                return Exit::ChecksumMismatch;
            }
        }
        if self.selected.is_empty() {
            // The banner still names the archive, and the blank line that
            // would follow it is the one `No files to extract` opens with.
            // Measured against `unrar` 7.23 on 19 Sep 2026: `x`, `t` and
            // `p -ierr` all read `Extracting from a.rar`, one blank line,
            // then the verdict.
            if self.announced.insert(0) {
                self.say(&format!(
                    "\n{} {}\n",
                    self.mode.banner(),
                    self.volume_names[0]
                ));
            }
            // Nothing matched, but a solid chain that holds a member the
            // engine refuses for its version is still read up to it, and
            // the reference finishes on that member.
            if let Some(index) = self.refused_in_a_solid_chain() {
                // On one stream the banner's blank line comes first, and
                // the complaint ends itself.
                if self.streams.one_stream() {
                    self.say("\n");
                }
                self.refuse_unknown(index);
                if self.streams.one_stream() {
                    self.say("No files to extract\n");
                } else {
                    self.say("\nNo files to extract\n");
                }
                self.end_muted_stderr();
                return Exit::Aborted;
            }
            self.say("\nNo files to extract\n");
            // Nothing matched, but the archive is still damaged, and the
            // reference finishes on the damage rather than on "nothing
            // matched". A header read through its failed checksum is said
            // here too: no run that met one is silent about it.
            let damaged = std::mem::take(&mut self.damaged);
            for header in &damaged {
                self.report_damaged_header(header);
            }
            return match self.tail {
                None if !damaged.is_empty() => Exit::ChecksumMismatch,
                None => Exit::NothingMatched,
                Some(Tail::Truncated) => {
                    self.report_truncation();
                    Exit::Cautioned
                }
                Some(Tail::CorruptHeader) => {
                    self.report_corrupt_header();
                    Exit::ChecksumMismatch
                }
            };
        }
        // A member the password cannot open never gets a line at the
        // reference: the complaint goes to stderr and the walk moves on,
        // which is why `extract-encrypted-wrong-password` shows only the
        // two `Creating` lines on stdout. Those members are dropped
        // before the walk so the engine is not asked to decode them.
        if self.password_wrong {
            // Indexed rather than iterated, and NOT cloned: the body
            // needs `&mut self` for `warn` and `done`, so a borrow of
            // `selected` cannot be held across it. The clone this
            // replaces was dodging exactly that, at the cost of copying
            // the whole vector per pass.
            for position in 0..self.selected.len() {
                let index = self.selected.at(position);
                if !self.plan[index].member.encrypted {
                    continue;
                }
                self.warn(&format!(
                    "\nIncorrect password for {}",
                    self.plan[index].member.name
                ));
                self.errors += 1;
                self.failures.push((index, Failure::Password));
                self.done.insert(index);
                self.touched = true;
            }
        }
        // A member whose continuation volume is missing cannot complete.
        // The reference still opens its line and still reports a checksum
        // failure for it, on top of the missing-volume one - but that
        // failure comes from the real walk reaching the member and
        // running off the end of the volumes in hand (`report_walk_error`'s
        // `Truncated` arm below), not from settling it here: every byte the
        // volumes in hand hold has already reached the sink by the time the
        // engine reports the gap (spec item 18), and `-kb` needs that file
        // to size the kept copy by.
        if let Some(name) = &missing_volume {
            // The reference names the volume it wanted before it reports
            // the member that then failed, so the complaint is emitted
            // before the walk rather than after it.
            self.warn(&format!("\nCannot find volume {name}"));
            self.errors += 1;
            self.failures.push((usize::MAX, Failure::LostVolume));
        }
        if matches!(self.mode, Mode::Extract { .. }) {
            self.pool_targets();
            self.snapshot_preexisting();
            self.may_ask = self.asks() && self.any_target_taken();
        }
        self.plan_redirects();
        // ONE walk, where the predecessor needed a restart loop.
        //
        // That engine's extraction was all-or-nothing: a member that
        // failed its checksum ended the whole walk, so this dialect
        // dropped that member's block from a clone of the archive and ran
        // the walk again, once per failure. rarkit reports a checksum
        // mismatch through `Sink::close` and carries on to the next
        // member (`MemberOutcome::checksum_ok`, `ExtractReport::
        // checksum_failures`), so the restart machinery - `one_pass`,
        // `retry_archives`, `dropped` as a retry set - has nothing to do
        // and is not carried. What it bought is unchanged: every member
        // still gets its line and its complaint, in archive order.
        let _ = password;
        for header in std::mem::take(&mut self.damaged) {
            self.report_damaged_header(&header);
        }
        if let Err(error) = self.walk() {
            self.report_walk_error(&error, missing_volume.is_some());
        }
        // After the walk, on both paths: the sequential and the concurrent
        // driver both return from `walk` only when every member is closed.
        finish_directories(std::mem::take(&mut self.dir_finish));
        match self.tail {
            None => {}
            Some(Tail::Truncated) => self.report_truncation(),
            Some(Tail::CorruptHeader) => self.report_corrupt_header(),
        }
        self.finish(missing_volume.is_some())
    }

    /// The whole member walk, through rarkit's `Sink`.
    ///
    /// The engine is handed the chain's volumes, each opened only when the
    /// walk reaches it (`engine::OnDemand`), and calls back once per member
    /// it opens, in archive order. Which plan entry a callback is about is
    /// read from what the engine says it opened ([`Walk`]), never counted.
    /// A volume the chain names but the
    /// disk does not have is already reported by `execute` as `Cannot find
    /// volume`; the walk runs over the parts that are there.
    pub(super) fn walk(&mut self) -> rarkit::Result<()> {
        let sources = crate::engine::OnDemand::new(self.volume_names.clone());
        // `-mt<n>` lands in TWO places, and it has to: the read's width
        // dial bounds the engine's own decode threads (API 8.4.2), while
        // the pool decides how many threads exist to wake at all, and the
        // measurement in `crate::workers` says the CPU tracks the pool.
        // The pool is sized FIRST, because the width the engine resolves
        // for a run with no `-mt` is the pool's own (8.4.3).
        // This is the extract AND test path: `Mode::Test` walks the same
        // code.
        let serial = self.opts.threads.is_none() && {
            let sizes = self.plan.iter().filter(|p| !p.member.is_dir);
            crate::workers::lone_small_member(sizes.map(|p| p.member.size))
        };
        // THE IDLE POOL (FROM-STUDIO 518 C, part (1)): one clear stored
        // member under a CRC32 of any larger size, whose route hands the
        // pool no job (`crate::workers::lone_clear_stored_member`), takes the
        // serial pool too, but keeps the read width it has today, stated
        // below: the engine's own threads for it (the seam, a wide read's
        // lanes) are sized by that width and not by the pool. Never with a
        // stated `-mt<n>` and never in a solid set (518 C (3)).
        let idle = self.opts.threads.is_none()
            && !serial
            && !self.volumes.iter().any(|v| v.solid)
            && crate::workers::lone_clear_stored_member(
                self.plan.iter().filter(|p| !p.member.is_dir).map(|p| {
                    let split =
                        p.fragments.len() > 1 || p.member.split_before || p.split_after_last;
                    (
                        p.member.method,
                        p.member.encrypted,
                        p.member.crc32.is_some(),
                        split,
                    )
                }),
            );
        // A plain stored set tested or printed cold off hard disks reads on
        // one thread, in order, where no width is stated
        // ([`ROTATIONAL_READERS`]).
        let (threads, in_order) =
            walk_threads(serial, self.opts.threads, || self.rotational_readers());
        // At one thread the rule is a stated `-mt1` in full: the volumes
        // the walk opens from here on take the sequential advice too.
        let advised = in_order && rotational_advice();
        if advised {
            crate::engine::advise_sequential_reads();
        }
        // COUNT ONLY (feature `read-depth-knob`): `RARFAST_ROTATIONAL_SAY=1`
        // says on stderr what the walk runs at, which is what
        // `tests/rotational_rule.rs` reads.
        #[cfg(feature = "read-depth-knob")]
        if std::env::var("RARFAST_ROTATIONAL_SAY").is_ok_and(|v| v.trim() == "1") {
            eprintln!("rarfast walk: threads {threads:?}; in order {advised}");
        }
        // An extract inside the open file limit (FROM-STUDIO 453 D): its
        // writers, twice its width, must fit the limit's share
        // (`crate::workers::extract_width_fit`). A width the limit cannot
        // hold is narrowed, and said so once, where none is stated; a
        // stated `-mt<n>` is a promise, so it is refused here, before a
        // member is read or a file created, never lowered.
        let fit = (matches!(self.mode, Mode::Extract { .. }) && !serial)
            .then(crate::workers::extract_width_fit)
            .flatten();
        if let Some((soft, fit)) = fit {
            let wide = crate::workers::width(threads, crate::workers::Work::Read);
            if wide > fit {
                let held = if fit == 1 { "thread" } else { "threads" };
                if let Some(stated) = self.opts.threads {
                    self.warn(&format!(
                        "\nCannot extract with -mt{stated}: the open file limit of {soft} \
                         holds {fit} {held} at most (raise it with ulimit -n, or name a \
                         smaller -mt)"
                    ));
                    self.errors += 1;
                    self.failures.push((usize::MAX, Failure::Unattributed));
                    return Ok(());
                }
                if crate::workers::first_width_note() {
                    self.warn(&format!(
                        "\nExtracting with {fit} {held}, not {wide}: the open file limit \
                         of {soft} holds no more (raise it with ulimit -n)"
                    ));
                }
            }
        }
        // The idle pool's read width: the width the pool would have been
        // built at, which with no `-mt<n>` is the width the engine resolved
        // from the pool (API 8.4.3) before this run had a serial one.
        let idle_width = idle.then(|| {
            crate::workers::width_within(
                threads,
                crate::workers::Work::Read,
                fit.map(|(_, fit)| fit),
            )
        });
        let pool = if serial || idle {
            crate::workers::configure_serial()
        } else {
            crate::workers::configure_within(
                threads,
                crate::workers::Work::Read,
                fit.map(|(_, fit)| fit),
            )
        };
        // A system that refuses the pool's threads is said here, in
        // rarfast's words, before a member is read or a file created: its
        // error was discarded until 1 Oct 2026 and the first use of the
        // pool then panicked (`crate::workers::configure`).
        if let Err(why) = pool {
            self.warn(&format!("\n{why}"));
            self.errors += 1;
            self.failures.push((usize::MAX, Failure::Unattributed));
            return Ok(());
        }
        let mut options = crate::engine::read_options_capped(
            self.opts.password.as_deref().map(str::as_bytes),
            threads,
            self.opts.memory_cap,
            self.plan_resident(),
        );
        if let Some(width) = idle_width {
            options = options.with_workers(Some(width));
        }
        // An extract to disk with no stated budget reads further ahead, for
        // the size of the slabs the seam writes past the cache
        // ([`EXTRACT_READ_AHEAD`]).
        if matches!(self.mode, Mode::Extract { .. }) && self.opts.memory_cap.is_none() {
            options.memory.read_ahead = extract_read_ahead();
        }
        // A set in small volumes that is NOT in memory has the volumes
        // after the one the walk opens asked for ahead
        // (`engine::volumes_ahead`): every extract, and a test or print of
        // stored members. A set already in memory has nothing to fetch, and
        // asking cost its extract 3 percent (an Apple M3 Mac, the big member in 859
        // volumes, warm `x` 3.21 s to 3.38 s), so the page cache is asked
        // first (`residency::of`, a sample of the first volume); a sample
        // that cannot be taken leaves the set as it was read before.
        let ahead = crate::engine::small_volumes_ahead_ruled();
        if ahead != crate::engine::Ahead::Off
            && crate::engine::ahead_command(
                matches!(self.mode, Mode::Extract { .. }),
                self.selected.iter().map(|index| {
                    let member = &self.plan[*index].member;
                    (member.is_dir, member.method)
                }),
            )
            && (ahead == crate::engine::Ahead::Always
                || self.volume_names.first().is_some_and(|first| {
                    crate::residency::of(Path::new(first)).1 == crate::residency::Residency::Cold
                }))
        {
            crate::engine::ask_small_volumes_ahead();
        }
        // A stored archive's route, and the depth a COLD clear one is read
        // at by the walk ([`Run::stored_route`]).
        #[cfg(feature = "parallel")]
        {
            let (walks, deep, stream) = self.stored_route();
            self.stored_walks = walks;
            // The depth of a cold stored archive is the SOURCE's
            // where the window is on ([`cold_window_of`]): the volumes the
            // walk opens from here on are read in order, two slabs ahead,
            // across members, and the engine keeps its shipped depth. An
            // encrypted archive is such a stream too, and without a window
            // it keeps the shipped depth: only a clear one reads deep.
            let window = cold_window_of(
                cold_window_knob(),
                stream,
                self.selects_every_file(),
                self.opts.memory_cap.is_some(),
                threads,
                options.memory.working_limit,
            );
            if let Some(slab) = window {
                crate::window::arm(slab);
                crate::window::arm_ahead(cold_window_ahead(cold_window_ask_knob()));
            }
            options.memory.read_ahead = stored_read_ahead(
                options.memory.read_ahead,
                deep && window.is_none(),
                self.opts.memory_cap.is_some(),
                options.memory.working_limit,
            );
            // ONE STORED MEMBER ALONE, IN MEMORY ([`lone_wide_stored`]): read
            // wide by the engine, its pieces checked where they are read
            // and written here in order, at a read-ahead of four readers.
            //
            // THIS STATEMENT IS NOT TRUE OF THE WRITER, AND SAYS SO. The
            // member's writer is a real file, and `Some(false)` says a
            // stream. It is stated ONLY to ask the engine for its wide read
            // of a written member, which the engine keys by this field and
            // by nothing else. The engine reads it as a cost class and
            // nothing more: it is never verified, and no byte, no verdict,
            // no order of writes and no memory bound moves with it
            // (`ReadOptions::sink_is_file`). The clean replacement is a
            // `ReadOptions` field or a `RangeSource` hint that asks for the
            // wide read by name: an item of the API's specification,
            // not this dialect's to add.
            if self.lone_wide(walks, window.is_some(), threads) {
                options.sink_is_file = Some(false);
                options.memory.read_ahead = LONE_WIDE_READ_AHEAD;
            }
        }
        // A SOLID set extracted to disk: each member's writer is a real
        // file, which is the cost class `ReadOptions::sink_is_file` names
        // (SPEC-API 8.5), and with it the engine hides the writes behind the
        // solid chain's decode (`read::sequential`, its solid path). Solid
        // sets only: a non-solid set's walk is unmeasured with the hint.
        if matches!(self.mode, Mode::Extract { .. }) && self.volumes.iter().any(|v| v.solid) {
            options.sink_is_file = Some(true);
        }
        // One large stored member beside small ones, walked
        // ([`lone_large_stored`]): where that member is under the size the
        // seam takes of every kind ([`SEAM_TAKES_ANY_FROM`]), the file cost class is
        // stated, so the seam takes it all the same and a second thread
        // writes it while the walk reads. Without it the walk reads and
        // writes such a member on one thread and loses to the pool (Linux,
        // a 300 MiB member in 15 MB volumes: 0.94x cold, against 1.28x
        // with it). Windows does not take a member that small
        // ([`LONE_LARGE_SMALL_FLOOR`]). Not where `RARFAST_POOL` forces the
        // pool.
        #[cfg(feature = "parallel")]
        if self
            .lone_large()
            .is_some_and(|size| size < SEAM_TAKES_ANY_FROM)
            && !takes_pool_of(pool_knob(), true)
        {
            options.sink_is_file = Some(true);
        }
        // COUNT ONLY (feature `read-depth-knob`, never shipped):
        // `RARFAST_X_SINK_FILE=1` states the file cost class for `x` and
        // `e` of ANY set, so the engine's seam takes a written member of
        // every size and not only one from its size floor (1 GiB): the arm
        // the cold stored several-members count prices a set of
        // like members under that floor with.
        #[cfg(feature = "read-depth-knob")]
        if matches!(self.mode, Mode::Extract { .. })
            && std::env::var("RARFAST_X_SINK_FILE").is_ok_and(|v| v.trim() == "1")
        {
            options.sink_is_file = Some(true);
        }
        // `p` writes to a stream, never a file on disk, which is the cost
        // class that lets a large stored member take the engine's wide read
        // (`read::wide`, SPEC-API 8.5): timed on a Zen 4, `p` of a 4.2 GiB
        // stored member 0.18 s to 0.09 s. `x` keeps `None` (since
        // 28 Sep 2026: its disk write is the wall, and the wide read
        // bought it nothing measurable). With or without a password: the
        // kept session is made with the same hint (`run`), so an `-hp` set
        // is still keyed once.
        //
        // Except a SOLID set printed into a regular file, which states the
        // file cost class as `x` of a solid set does, so the engine walks the
        // chain on a worker and the writes no longer stop the decode
        // (`payload::states_file`, which says why a pipe is not). Its
        // kept session was made with `Some(false)`, so, as for `x`, the walk
        // is keyed afresh (`Run::drive`).
        if self.mode == Mode::Print {
            let solid = self.volumes.iter().any(|v| v.solid);
            options.sink_is_file = Some(payload::states_file(solid));
        }
        // `t` and `p` with no stated budget read deeper on macOS, for the
        // wide read's readers ([`TEST_READ_AHEAD`]). Not a solid set printed
        // into a regular file (the case just above): that one runs under the
        // seam, whose ring is the read-ahead, and it was timed at the
        // engine's default, as this lever was timed without it.
        if matches!(self.mode, Mode::Test | Mode::Print)
            && self.opts.memory_cap.is_none()
            && options.sink_is_file != Some(true)
        {
            options.memory.read_ahead = test_read_ahead(options.memory.read_ahead);
            // A read wider than that read-ahead holds pieces for takes a
            // piece a lane ([`wide_test_read_ahead`]), behind its knob. A
            // set of ONE volume only: a member split across volumes is
            // read fragment by fragment, and there the deeper read-ahead
            // lost ([`wide_test_read_ahead`], "one volume"). And only where
            // the stored members it reads are large ones with a CRC32
            // ([`tp_window_members`]).
            let deeper = match tp_window_knob() {
                TpWindow::Off => false,
                TpWindow::Always => true,
                TpWindow::Rule => {
                    self.volume_names.len() == 1
                        && tp_window_members(
                            self.selected.iter().map(|index| &self.plan[*index].member),
                        )
                }
            };
            if deeper {
                options.memory.read_ahead = wide_test_read_ahead(
                    options.memory.read_ahead,
                    options.read_width(),
                    options.memory.working_limit,
                );
            }
        }
        // As the kept session states it (`run`).
        let waiting = waiting_outputs(self.mode, &self.dest, options.read_width());
        // The reserve asks whether the seam can take a member at all
        // (`output::no_room_from`): at a width of one it cannot.
        output::state_read_width(options.read_width());
        let options = options
            .with_waiting_outputs(waiting)
            .with_files_in_order(files_in_order(self.mode));
        // `h2-probes` builds only (no shipped build reads it):
        // `RARFAST_POOL_SAY=1` says the width the engine reads at, beside
        // the pool's own line (`crate::workers`), which
        // `tests/idle_pool.rs` reads.
        #[cfg(feature = "h2-probes")]
        if std::env::var("RARFAST_POOL_SAY").is_ok_and(|v| v.trim() == "1") {
            eprintln!("rarfast read: width {}", options.read_width());
        }
        self.window_ceiling = options.memory.max_window;
        self.narrowing = (self.opts.threads.is_some() && self.opts.memory_cap.is_some())
            .then_some(options.memory);
        let outcome = self.drive(sources, &options);
        // A walk that ended well opened every member it was going to: an
        // entry this run owes that it never opened is said, by name.
        if outcome.is_ok() && self.stopped.is_none() {
            for index in self.reached..self.plan.len() {
                if self.owes(index) {
                    self.refuse_unopened(index);
                }
            }
        }
        // A member's WRITE failed (the only code of this dialect's that
        // the walk runs and that can fail): the run ends there, as the
        // reference's does, and what the concurrent walk had begun beyond
        // it and not yet said is not said (`Run::drop_unsaid`).
        if let Err(error) = &outcome {
            if matches!(error.kind(), rarkit::ErrorKind::Caller)
                && matches!(self.mode, Mode::Extract { .. })
            {
                self.drop_unsaid();
            }
        }
        // Whatever ELSE the walk did, nothing a member printed is dropped: an
        // operation-ending error leaves the members the concurrent walk
        // had run ahead to never closed, and their lines are this run's
        // account of how far it got. See `Run::drain_all`.
        self.drain_all();
        self.say_narrowed();
        outcome
    }

    /// A member is about to be read: where the user named a width and a
    /// memory limit, keep the narrowest width the limit holds any RAR 5
    /// member to. A member that is decoded on one thread whatever the
    /// limit, and a format that is read in sequence, narrow nothing.
    ///
    /// NOT SAID: a solid chain's look-ahead, which the limit bounds by its
    /// own share. SPEC-CLI 14's line is about a member read at fewer
    /// threads than `-mt` asked, and the look-ahead is how far ahead of
    /// the member in hand the chain decodes, not a width a member is read
    /// at; a chain whose members are themselves narrowed is said like any
    /// other.
    pub(super) fn note_width(&mut self, member: &rarkit::MemberInfo<'_>) {
        let (Some(policy), Some(asked)) = (self.narrowing, self.opts.threads) else {
            return;
        };
        let Some(dictionary) = member.dictionary else {
            return;
        };
        if member.algorithm_version > 1 {
            return;
        }
        let unpacked = member.unpacked_size.unwrap_or(dictionary);
        let window = if member.solid {
            dictionary
        } else {
            dictionary.min(unpacked)
        };
        let Some(width) = policy.member_width(window, unpacked) else {
            return;
        };
        if (width as u64) < asked {
            self.narrowest = Some(self.narrowest.map_or(width, |least| least.min(width)));
        }
    }

    /// SPEC-CLI 14: one line for the run, on standard error, where the
    /// memory limit ran a member at fewer threads than `-mt` asked for. A
    /// note and not an error; `-inul` prints none of it.
    fn say_narrowed(&self) {
        let (Some(width), Some(asked)) = (self.narrowest, self.opts.threads) else {
            return;
        };
        if self.opts.silent {
            return;
        }
        eprintln!(
            "ran at {width} thread{}, not the {asked} asked for: the memory limit leaves room for no more",
            if width == 1 { "" } else { "s" }
        );
    }

    /// Runs the walk through the engine entry point this command wants.
    ///
    /// **Concurrent unless the command's bytes say otherwise.**
    /// `extract_parallel` decodes the independent members of a non-solid
    /// set on worker threads and hands each its own writer, which is where
    /// the wall of `x`, `e` and `t` comes from.
    /// It makes the same bytes per member as `extract` and closes members
    /// in archive order, and it decides for itself which members it may
    /// take: a solid chain, a member split across volumes and a member too
    /// small to pay for a worker all stay on the walking thread.
    ///
    /// **`p` is the first exception, and it is not a tuning choice.** That
    /// command writes every member's bytes to ONE stream, standard output,
    /// and those bytes are the point of it. Two members decoded at once
    /// would each write into that stream while the other was writing, so
    /// the payload would interleave and the command would be wrong rather
    /// than slow. The other three give each member a writer of its own -
    /// its output file, or nothing at all for `t` - so there is no shared
    /// stream to corrupt.
    ///
    /// **A SOLID archive is the second, and it is measured.** Every member
    /// of a solid chain begins in the window the member before it left
    /// (spec F 3.6), so the engine decodes them all on the walking thread
    /// whichever entry point is called. What the concurrent driver still
    /// does for such a member is hand its WRITES to a worker, and on a
    /// solid set that pipe costs more than it saves: eight 16 MiB members
    /// at `-m3`, seven rounds on an 18 core aarch64 laptop at a one minute
    /// load of 5.8, read
    ///
    /// | command | sequential | through the pool | ratio |
    /// |---|---|---|---|
    /// | `t` (no writes at all) | 41.7 ms | 41.6 ms | 1.004x |
    /// | `x` | 53.5 ms | 68.8 ms | **0.779x** |
    ///
    /// `t` is flat because it writes nothing, which is what says the loss
    /// IS the write pipe and not the driver's bookkeeping. So a solid
    /// archive takes the sequential entry point, where its writes go
    /// straight to the file as they did before. A caller loses nothing by
    /// it: there was no decode parallelism there to lose.
    ///
    /// The engine makes the same judgement per MEMBER for a stored member
    /// below its offload floor, which is why an archive of many small
    /// members was unaffected either way (0.96x to 1.04x on the same
    /// sweep); a compressed one it takes in small batches since 26 Sep
    /// 2026. What it
    /// does not have is a reason to decline the pipe for a whole solid
    /// SET, and whether it should is **open**: the
    /// figures above are this crate's and the decision would be the
    /// engine's.
    ///
    /// **A BREADTH OF ONE is the third, and it is the same finding.**
    /// `-mt1` leaves the engine one unit of decode in flight, so no two
    /// members are ever decoded at once and the concurrent driver is again
    /// down to its write pipe. Measured on the same seven rounds, `-mt1`
    /// bought nothing anywhere - 0.998x to 1.038x on every leg - and cost
    /// **0.951x** on the volume set's `x`, reproduced across two sweeps.
    /// So `-mt1` takes the sequential path, which makes the switch mean
    /// exactly what it meant before this change: one member at a time,
    /// through the code that has always done it.
    ///
    /// **TWO MEMBERS WRITTEN TO ONE FILE are the fourth, and it is the
    /// bytes again.** The pool opens the later member's file, which empties
    /// it, while a worker still writes the earlier one. See `twins`.
    pub(super) fn drive(
        &mut self,
        sources: crate::engine::OnDemand,
        options: &rarkit::ReadOptions,
    ) -> rarkit::Result<()> {
        // Taken, not borrowed: the walk's sink holds the run itself. The
        // command walks once, so nothing else wants it back.
        let mut session = self.session.take();
        let entered = sources.entered();
        let ordered = self
            .plan
            .windows(2)
            .all(|pair| pair[0].fragments[0] < pair[1].fragments[0]);
        #[cfg(feature = "parallel")]
        if !self.may_ask
            && pool_drives(
                self.mode == Mode::Print,
                self.volumes.iter().any(|volume| volume.solid),
                self.any_selected_is_split(),
                self.breadth(options),
                self.takes_pool(),
            )
            // Two members written to one file settle in archive order:
            // such a run takes the in-order walk below, and says so
            // (`twins`).
            && !self.falls_back_to_one_at_a_time()
        {
            let breadth = self.breadth(options);
            // Plain members' files made ahead of the walk and closed behind
            // it, on Linux (`ahead`); ended, whatever the walk's outcome,
            // before anything else is said or finished.
            //
            // NEVER FOR A LONE MEMBER, which is why the walking thread may
            // be such a run's whole pool (`crate::workers::configure_serial`,
            // FROM-STUDIO 518 C's precondition). The helpers are
            // `rayon::spawn`ed and then waited for (`Ahead::stop`), and a
            // serial pool runs no spawned job on its own. Three guards keep
            // them off, each enough alone: one selected member is a breadth
            // of one ([`Self::breadth`]), so `pool_drives` refuses this
            // branch and the helpers are never armed; `arm_ahead` arms none
            // on a pool narrower than two; and it arms none for fewer than
            // `FEWEST` (64) members, where one member is one item at most.
            #[cfg(target_os = "linux")]
            self.arm_ahead(breadth);
            // And on macOS, with its own helper count (`ahead`).
            #[cfg(target_os = "macos")]
            self.arm_ahead(breadth);
            // `h2-probes` builds only: which driver ran, beside the pool's
            // line; create ahead is armed on this one alone, so a run that
            // says `walk` armed no helper (`tests/idle_pool.rs`).
            #[cfg(feature = "h2-probes")]
            say_drive("pool");
            let walked = {
                let sink = ConcurrentSink {
                    walk: std::sync::Mutex::new(Walk {
                        run: &mut *self,
                        expect: 0,
                        closing: VecDeque::new(),
                        buffered: true,
                        entered,
                        ordered,
                        unlisted: 0,
                    }),
                };
                match session.as_mut() {
                    Some(session) => session.extract_parallel(sources, &sink, breadth),
                    None => rarkit::extract_parallel(sources, options, &sink, breadth),
                }
            };
            #[cfg(target_os = "linux")]
            self.end_ahead();
            #[cfg(target_os = "macos")]
            self.end_ahead();
            walked?;
            return Ok(());
        }
        #[cfg(feature = "h2-probes")]
        say_drive("walk");
        let mut sink = DialectSink {
            walk: Walk {
                run: self,
                expect: 0,
                closing: VecDeque::new(),
                buffered: false,
                entered,
                ordered,
                unlisted: 0,
            },
        };
        // The kept session reads with the walk's options except where the
        // walk adds `sink_is_file` for a solid set, so it serves only when
        // its hint is the walk's (none, or `p`'s); otherwise the read is
        // keyed afresh, as before.
        match session.as_mut() {
            Some(session) if session.options().sink_is_file == options.sink_is_file => {
                session.extract(sources, &mut sink, &mut ())?;
            }
            _ => {
                rarkit::extract(sources, options, &mut sink, &mut ())?;
            }
        }
        Ok(())
    }

    /// One `Unexpected end of archive`, counted.
    pub(super) fn report_truncation(&mut self) {
        self.walk_ended(UNEXPECTED_END);
        self.errors += 1;
        self.failures.push((usize::MAX, Failure::Truncated));
    }

    /// A header that was read although its own checksum failed: the
    /// reference's lines for it and its count ([`DamagedHeader`]), and
    /// exit 3. Said before the walk, which then tests or extracts every
    /// member, the one behind that header included.
    fn report_damaged_header(&mut self, header: &DamagedHeader) {
        for line in &header.lines {
            self.walk_ended(&format!("\n{line}"));
        }
        self.errors += header.errors;
        self.failures.push((usize::MAX, Failure::CorruptHeader));
    }

    /// One `Corrupt header is found`, counted.
    ///
    /// Or, where the headers are enciphered with no password check (the
    /// RAR 1.5 to 4.x family's `-hp`), the reference's sentence that cannot
    /// tell a wrong password from damage, naming the archive, in the
    /// layout of a member's complaint: `\n<sentence>` apart, `<sentence>\n`
    /// after the line before it on one stream. Measured against unrar 7.23
    /// on 30 Sep 2026 over rar 4.20's `r420_hp.rar` given the right
    /// password with a later header damaged, `t` and `-ierr`, exit 3.
    pub(super) fn report_corrupt_header(&mut self) {
        match self.unchecked_header_text() {
            Some(text) if self.streams.one_stream() => self.warn(&format!("{text}\n")),
            Some(text) => self.warn(&format!("\n{text}")),
            None => self.walk_ended(CORRUPT_HEADER),
        }
        self.errors += 1;
        self.failures.push((usize::MAX, Failure::CorruptHeader));
    }

    /// `Unexpected end of archive` or `Corrupt header is found` (`text`,
    /// which opens with its newline), where the walk stopped: apart, on
    /// stderr and unended; on one stream (`-ierr`) the line before it has
    /// ended, so it follows directly and ends itself, and `Total errors`
    /// comes after it. Measured against unrar 7.23 on 30 Sep 2026 over
    /// RAR 5 and rar 4.20 archives cut inside a member's data and inside a
    /// later header, `t` and `x`.
    pub(super) fn walk_ended(&mut self, text: &str) {
        if self.streams.one_stream() {
            self.warn(&format!("{}\n", text.trim_start_matches('\n')));
        } else {
            self.warn(text);
        }
    }

    /// The reference's words for a header that failed in an archive whose
    /// headers are enciphered with no password check, or `None`.
    pub(super) fn unchecked_header_text(&self) -> Option<String> {
        self.volumes
            .first()
            .is_some_and(|first| first.headers_unchecked)
            .then(|| {
                format!(
                    "Checksum error in the encrypted file {}. Corrupt file or wrong password.",
                    self.volume_names[0]
                )
            })
    }

    /// The member whose line was open when the walk ran into the damage:
    /// its line closes with the reference's checksum complaint, and its
    /// file is kept or removed as a checksum failure's is, on `-kb`.
    /// `Sink::close` is never called for it, so nothing else settles it.
    pub(super) fn settle_cut_member(&mut self, index: usize) {
        self.errors += 1;
        self.failures.push((index, Failure::Checksum));
        let name = self.plan[index].member.name.clone();
        self.complain(&name, "- checksum error");
        self.finish_member(index, false);
        // Only a file this run WROTE may be removed. With no line open,
        // `stopped_on` can name a member whose create failed (an existing
        // read-only file under `-y`), and its target is the caller's own
        // file.
        self.discard_failed(index);
        self.done.insert(index);
    }
}

/// `RARFAST_POOL_SAY=1` (`h2-probes` builds only): which driver the walk
/// took, `pool` or `walk` ([`Run::drive`]).
#[cfg(feature = "h2-probes")]
fn say_drive(driver: &str) {
    if std::env::var("RARFAST_POOL_SAY").is_ok_and(|v| v.trim() == "1") {
        eprintln!("rarfast drive: {driver}");
    }
}
