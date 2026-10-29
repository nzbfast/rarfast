//! One member opened: what is said of it, and the file created for it.

use super::*;

impl Run<'_> {
    /// A member's output file created CACHED under `policy`: the path every
    /// member takes but a big one on Windows, and that one's fall back.
    pub(super) fn create_cached(
        &self,
        target: &Path,
        policy: crate::safepath::IfOutputExists,
        create: u32,
    ) -> std::io::Result<Option<crate::safepath::Created>> {
        // A LINK at the path is a taken name like any other (SPEC-CLI 9.4
        // W8): the exclusive create is refused by it, the member is
        // written beside it, and the link goes only when the member takes
        // the name. Nothing is removed here.
        crate::safepath::make_member_file(target, policy, create)
    }

    /// A member that could not be created: the reference's two lines on
    /// stderr, the path and the system's reason, counted, exit 9, and NO
    /// progress line (unrar 7.23, 2 Oct 2026, files with the immutable
    /// flag and a file in a directory that may not be written; plain,
    /// `-idq` and `-ierr`). Until then the line was opened first and the
    /// complaint read `<name> - cannot create`, with no reason.
    ///
    /// A path that is a DIRECTORY gets the reference's third line.
    ///
    /// A DIRECTORY member that could not be made is said the same way, as
    /// `Cannot create directory <name>` (unrar 7.23, 10 Oct 2026, a
    /// directory under a regular file: the same two lines in the same
    /// places, plain, `-idq`, `-ierr` and `-idn`, exit 9).
    pub(super) fn refuse_create(
        &mut self,
        index: usize,
        target: &Path,
        shown: &str,
        err: &std::io::Error,
    ) {
        // Counted AND recorded: the exit code is built from `failures`.
        self.errors += 1;
        self.failures.push((index, Failure::Create));
        // `-idn`: a member that fails ends the line of counters before it
        // (or the banner's), once; `finish` then has no line to end.
        if self.opts.hide_names && !self.last_failed {
            self.say("\n");
        }
        self.banner_gap_owed = false;
        self.last_failed = true;
        // A directory member is named as one, and has no third line.
        let is_dir = self.plan[index].member.is_dir;
        let what = if is_dir { "directory " } else { "" };
        let mut text = format!("Cannot create {what}{shown}\n{}", super::io_reason(err));
        if !is_dir && target.is_dir() {
            text.push_str("\nDirectory with such name already exists");
        }
        if self.streams.one_stream() {
            self.warn(&format!("{text}\n"));
        } else {
            self.warn(&format!("\n{text}"));
        }
        self.done.insert(index);
    }

    /// `e` into a named destination, and a FILE whose name is all path
    /// (`d/`): the reference tries to create the destination's own name
    /// as the file and says so, three lines on stderr, counted, exit 9,
    /// with no progress line; alone it closes with `No files to
    /// extract` (SPEC-CLI 2.1 M18; rar and unrar 7.23, aarch64 macOS, 11
    /// Oct 2026: `e arc.rar dst/` says `Cannot create dst/`, `Is a
    /// directory`, `Directory with such name already exists`).
    ///
    /// NOTHING is touched on disk for it here: no file, and no
    /// destination directory made for its sake, where the reference
    /// first makes a destination that is not there.
    pub(super) fn refuse_destination_itself(&mut self, index: usize) {
        // Counted AND recorded: the exit code is built from `failures`.
        self.errors += 1;
        self.failures.push((index, Failure::Create));
        if self.opts.hide_names && !self.last_failed {
            self.say("\n");
        }
        self.banner_gap_owed = false;
        self.last_failed = true;
        // The reason the system gives for opening a directory to write.
        #[cfg(unix)]
        let reason = super::io_reason(&std::io::Error::from_raw_os_error(21));
        #[cfg(not(unix))]
        let reason = super::io_reason(&std::io::Error::from(std::io::ErrorKind::IsADirectory));
        let text = format!(
            "Cannot create {}\n{reason}\nDirectory with such name already exists",
            self.dest
        );
        if self.streams.one_stream() {
            self.warn(&format!("{text}\n"));
        } else {
            self.warn(&format!("\n{text}"));
        }
        self.done.insert(index);
    }
}

impl Run<'_> {
    /// Opens one member: the reference's line for it first, then where its
    /// bytes go.
    ///
    /// Carried from the predecessor's callback of the same name, with the
    /// engine's `ExtractedEntryMeta` replaced by the one fact it read out
    /// of it (`is_directory`) and the return type replaced by rarkit's
    /// [`Disposition`], which says SKIP rather than handing back a sink to
    /// throw away. The concurrent-writer slots are not carried: they
    /// belonged to the predecessor's own worker pool, and rarkit's
    /// parallel entry point takes a `ParallelSink` instead. Restoring
    /// concurrent writes on top of it is not done yet.
    pub(super) fn begin_member(
        &mut self,
        index: usize,
        is_directory: bool,
        redirection: Option<rarkit::Redirection<'_>>,
        over_window: bool,
    ) -> Disposition<Box<dyn Write + Send>> {
        let disposition = self.open_member(index, is_directory, redirection, over_window);
        let Some(capture) = self.capture.take() else {
            return disposition;
        };
        match disposition {
            // No close will come for it: nothing is held for one.
            Disposition::Skip => {
                if !capture.text.is_empty() {
                    self.say(&capture.text);
                }
                Disposition::Skip
            }
            opened => {
                let text = Arc::new(Mutex::new(Some(capture.text)));
                let opened = match opened {
                    // `p`'s heading goes out before the member's first
                    // byte, so a caller reading both streams as one sees
                    // it first.
                    Disposition::Write(inner) if self.mode == Mode::Print => {
                        Disposition::Write(Box::new(ReleaseFirst {
                            inner,
                            held: Arc::clone(&text),
                            streams: self.streams.beside_payload(),
                        }) as Box<dyn Write + Send>)
                    }
                    other => other,
                };
                self.held.insert(
                    index,
                    Held {
                        text,
                        dirs: capture.dirs,
                    },
                );
                opened
            }
        }
    }

    /// [`Run::begin_member`]'s body: everything it says and makes, which
    /// for an encrypted member is captured (see [`Run::held`]).
    pub(super) fn open_member(
        &mut self,
        index: usize,
        is_directory: bool,
        redirection: Option<rarkit::Redirection<'_>>,
        over_window: bool,
    ) -> Disposition<Box<dyn Write + Send>> {
        // Stopped at the question about a file already there: nothing after
        // it is opened. The sequential walk ends at that member's `open`;
        // this is the pool's, whose members in flight still finish.
        if index >= self.plan.len() || self.stopped.is_some() {
            return Disposition::Skip;
        }
        // A copy's target this run was not asked for is decoded into the
        // copy instead (spec F 3.8.5).
        if matches!(self.mode, Mode::Extract { .. }) && !self.selected.contains(index) {
            if let Some(fed) = self.feed(index) {
                return fed;
            }
        }
        if self.done.contains(index) || !self.selected.contains(index) {
            // A member this run does not take, which the engine will
            // refuse for its version: in a solid archive the members
            // behind it cannot be had (`Run::chain_stops_at`).
            if self.plan[index].member.unknown_version && !self.done.contains(index) {
                self.chain_stops_at(index);
            }
            return Disposition::Skip;
        }
        let (volume, data_end) = self.plan[index].fragments[0];
        // The banner of a volume an earlier member CONTINUES into is that
        // member's to print, before its `...` line there (`continue_member`):
        // the concurrent walk opens this member before the earlier one's
        // close, and announcing here put the banner after the earlier
        // member's last lines. Measured against unrar 7.23 on 30 Sep 2026,
        // `x` over a RAR 5 set of a 3 MB member across three volumes and a
        // 200 KB one starting in the third.
        if !self.continued_into(index, volume) {
            if self.announce_passed {
                for passed in 0..volume {
                    self.announce(passed);
                }
            }
            self.announce(volume);
        }
        // After the banner, which the reference prints for a refused member
        // too: what follows is held until its password is judged, or, for a
        // member whose dictionary is above the policy's window, until it is
        // known not to be refused for it. The reference prints no line for
        // a member it refuses (see the unknown version below), and the
        // engine refuses a window after this `open`, before any byte
        // (`Run::report_walk_error`). Only such members are
        // held, so an ordinary archive pays nothing for it.
        if self.plan[index].member.encrypted || over_window {
            self.capture = Some(Capture::default());
        }
        // A member the engine will refuse for its version, known from its
        // header (spec F 3.2.6, 3.3.5): no progress line, and nothing on
        // disk, not even an existing file of its name touched. Measured
        // against unrar 7.23 on 28 Sep 2026 (two and three RAR 5 members
        // at compression version 2, two and three RAR 4 members at unpack
        // version 36; `t`, `x`, `e`, `p`): it prints no line for such a
        // member, `x -o+` leaves an existing file of its name as it was,
        // and `x -kb` leaves none. `Verify` still brings its `close`,
        // where it is named ([`Run::refuse_unknown`]). Nor does it count
        // as processed: selected alone, the reference closes with `No
        // files to extract`, exit 2 ([`Run::finish`]).
        if self.plan[index].member.unknown_version && redirection.is_none() {
            return Disposition::Verify;
        }
        // A member with no name at all is passed over by every command:
        // no line, no byte printed, nothing made, and not processed. And
        // a directory is not processed by `e` or by `p`, which have
        // nothing to do with one. Measured against unrar 7.23 for macOS,
        // 10 Oct 2026 (`tests/nothing_processed_exit.rs`): an archive of
        // either alone closes with `No files to extract`, exit 10. Both
        // counted as processed until then.
        if self.plan[index].member.disk_name().is_empty() {
            self.done.insert(index);
            return Disposition::Skip;
        }
        let passed_over = is_directory
            && redirection.is_none()
            && matches!(self.mode, Mode::Print | Mode::Extract { flat: true });
        // A FILE or a link that `x` or `e` writes counts once it is made
        // ([`Run::touched`]): one kept because its path was taken, or one
        // that could not be created, was not processed.
        let written = matches!(self.mode, Mode::Extract { .. }) && !is_directory;
        if !written && !passed_over {
            self.touched = true;
        }
        // Never delivered as bytes (spec F 3.8.1): `p` has nothing to
        // print for one, and `t`, `x` and `e` settle it at its `close`.
        // The record wins over the directory flag, which the Windows
        // writer sets on a directory link and a junction (MEASURED on
        // Rar.exe 7.23, a Windows desktop, 27 Sep 2026): such a member is a link,
        // never a directory made in its place.
        if let Some(redirection) = redirection {
            if self.mode == Mode::Print {
                self.done.insert(index);
                return Disposition::Skip;
            }
            return self.begin_redirect(index, redirection);
        }

        match self.mode {
            Mode::Test => {
                if is_directory {
                    let name = self.plan[index].member.name.clone();
                    if !self.opts.hide_names {
                        self.say(&format!(
                            "{}OK\n",
                            separated(
                                &format!("{:VERB_WIDTH$}{name}", "Testing"),
                                DIR_NAME_COLUMN,
                                2,
                            )
                        ));
                    }
                    self.done.insert(index);
                    return Disposition::Skip;
                }
                // The line is only ever printed, through `say`, so a run
                // whose `say` writes nothing does not copy the name for it.
                if self.streams.says() {
                    let name = self.plan[index].member.name.clone();
                    self.open_progress("Testing", &name, volume, data_end);
                }
                self.open_lines.insert(index);
                Disposition::Verify
            }
            Mode::Print => {
                if !is_directory {
                    // Only the line is skipped where `say` writes nothing
                    // (`p` without `-ierr`), never the open-line record:
                    // a damaged member's complaint is decided from it.
                    if self.streams.says() {
                        let name = self.plan[index].member.name.clone();
                        self.open_progress("Printing", &name, volume, data_end);
                    }
                    self.open_lines.insert(index);
                }
                Disposition::Write(payload::writer())
            }
            Mode::Extract { flat } => {
                // The pool is lent out for the member: the path borrowed
                // from it lives across calls that need the run mutably.
                let targets = std::mem::take(&mut self.targets);
                let disposition =
                    self.begin_extract(index, is_directory, flat, volume, data_end, &targets);
                self.targets = targets;
                self.feed_kept().unwrap_or(disposition)
            }
        }
    }

    /// [`Run::begin_member`] for `x` and `e`, with the output path read
    /// from `targets`, the run's pool (see [`Run::pool_targets`]).
    pub(super) fn begin_extract(
        &mut self,
        index: usize,
        is_directory: bool,
        flat: bool,
        volume: usize,
        data_end: u64,
        targets: &str,
    ) -> Disposition<Box<dyn Write + Send>> {
        // Only ever printed, through `say`: a run whose `say` writes
        // nothing (`-idq`, `-inul`) does not build it.
        let shown = if self.streams.says() {
            self.member_display_name(index)
        } else {
            String::new()
        };
        let owned;
        let target: &Path = match self.target_at.get(index) {
            Some(Target::Pooled(start, end)) => Path::new(&targets[*start..*end]),
            Some(Target::Owned(path)) => {
                owned = path.clone();
                &owned
            }
            // Nothing to write and nothing to say: the reference
            // extracts a member with no on-disk name silently.
            Some(Target::Nameless) => {
                self.touched |= !is_directory;
                self.done.insert(index);
                return Disposition::Skip;
            }
            Some(Target::DestinationItself) => {
                self.refuse_destination_itself(index);
                return Disposition::Skip;
            }
            Some(Target::Unresolved | Target::Refused) | None => {
                self.touched = true;
                self.refuse_unsafe_name(index);
                return Disposition::Skip;
            }
        };
        // Windows: a path past 4,096 characters is refused by name before
        // anything is made for it, as Linux's PATH_MAX refuses it there.
        if let Some(err) = Self::too_long(target) {
            if !(is_directory && flat) {
                let said = self.member_display_name(index);
                self.refuse_create(index, target, &said, &err);
                return Disposition::Skip;
            }
        }
        if is_directory {
            if flat {
                self.done.insert(index);
                return Disposition::Skip;
            }
            // The destination is announced before the member's own
            // directory, and a run whose every FILE failed its
            // password still shows both lines.
            self.ensure_dest();
            let existed = self.logically_exists(target);
            let member = &self.plan[index].member;
            let stored = DirMode::of(
                member.host,
                member.attr,
                self.opts.ignore_attributes,
                existed,
            );
            // SPEC-CLI 9.4 W10 (c): the three bits above the nine are the
            // superuser's for a directory member as for a file (W3), and
            // a run that left them off says so once.
            let decided = if mode::superuser() {
                stored
            } else {
                if stored.has_high_bits() {
                    self.high_bits_left_off
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                stored.without_high_bits()
            };
            let mut left_with = mode::dir_finish(decided);
            if left_with.is_some() && left_with == self.made_modes.get(target).copied() {
                left_with = None;
            }
            if !existed {
                // The missing parents are announced as a file member's
                // are, outermost first, each once in a run (unrar 7.23
                // for macOS, 10 Oct 2026: `x` of the one member `a/b`
                // prints `Creating` for `a` and then for `a/b`; they were
                // made without a word until then). Each a real directory
                // before the directory is made with its mode:
                // `create_dir_all` would follow a link in any component
                // (spec F 3.8.3). A level still a link is not walked.
                if !self.ensure_parents(target) {
                    self.refuse_through_link(index);
                    return Disposition::Skip;
                }
                // What stands at the directory's own path (unrar 7.23,
                // 11 Oct 2026, and the decisions of that day).
                //
                // A FILE there is the caller's, and the reference's rule
                // for it is the overwrite rule: `-o+` and `-y` REPLACE it
                // by the directory; the default rule ASKS, with no new
                // name on offer; `-or` makes the directory under the next
                // free numbered name and leaves it; `-o-` leaves it, and
                // the directory is then a create error below.
                //
                // A LINK there is NEVER FOLLOWED and is handled as that
                // file in the way, whatever it leads to (spec F 3.8.3, one
                // rule with the parents of a file member): under `-o+`
                // and `-y` the LINK is replaced by a real directory, and
                // what it names is untouched. Two stated differences from
                // the reference follow from it: a link to a DIRECTORY the
                // reference leaves as it is where the directory member
                // stands alone (it takes the link for the directory), and
                // a link to NOTHING it refuses under every switch.
                //
                // One look, and what is removed is the entry at the path.
                let mut numbered: Option<(PathBuf, String)> = None;
                let in_the_way = fs::symlink_metadata(target)
                    .ok()
                    .filter(|there| there.file_type().is_symlink() || !there.is_dir());
                if let Some(there) = in_the_way {
                    let said = self.member_display_name(index);
                    let replace = if self.may_overwrite() {
                        true
                    } else if self.asks() || self.opts.overwrite == Overwrite::Rename {
                        match self.settle_existing(index, target, &said, false) {
                            Standing::Replace => true,
                            Standing::Stop => {
                                self.done.insert(index);
                                return Disposition::Skip;
                            }
                            Standing::Renamed(path, name) => {
                                numbered = Some((path, name));
                                false
                            }
                            Standing::Keep => false,
                        }
                    } else {
                        false
                    };
                    if replace {
                        if there.file_type().is_symlink() {
                            links::unlink(target);
                        } else {
                            let _ = fs::remove_file(target);
                        }
                    }
                }
                // `-or`: the directory is made, announced and finished
                // under its numbered name from here on.
                if let Some((path, name)) = numbered {
                    self.target_at[index] = Target::Owned(path.clone());
                    return self.make_numbered_directory(index, &path, &name, decided, left_with);
                }
                let made = mode::create_directory(target, decided);
                match made {
                    Ok(made) if links::is_real_dir(target) => {
                        left_with = left_with.or(made);
                        self.dirs.make(target.to_path_buf());
                        self.creating(&shown);
                    }
                    // Not made: a file in its place, or in the place of a
                    // directory above it, or a system that refused. A
                    // create error like a file's, and nothing queued to be
                    // set on whatever stands at the path. Until 10 Oct 2026
                    // this fell through to the member counted as done: `All
                    // OK`, exit 0 and no directory, and the directory's mode
                    // set on the file in the way when the walk ended.
                    made => {
                        let err = made.err().unwrap_or_else(|| {
                            std::io::Error::from(std::io::ErrorKind::AlreadyExists)
                        });
                        // A file in the place of a directory ABOVE it is
                        // the system's `Not a directory`, as the reference
                        // has it; making the levels above first reports it
                        // as a file that exists.
                        let err = match fs::symlink_metadata(target) {
                            Err(above) if above.kind() == std::io::ErrorKind::NotADirectory => {
                                above
                            }
                            _ => err,
                        };
                        let said = self.member_display_name(index);
                        self.refuse_create(index, target, &said, &err);
                        return Disposition::Skip;
                    }
                }
            }
            let mtime = self.mtime_to_set(&self.plan[index].member);
            if left_with.is_some() || mtime.is_some() {
                self.dir_finish.push(DirFinish {
                    path: target.to_path_buf(),
                    mode: left_with,
                    mtime,
                });
            }
            self.done.insert(index);
            return Disposition::Skip;
        }
        self.ensure_dest();
        if !self.ensure_parents(target) {
            self.touched = true;
            self.refuse_through_link(index);
            return Disposition::Skip;
        }
        // The path this member is written to and the name its line shows:
        // the member's own, unless the caller answered the question about
        // a file already there with a new one.
        let mut renamed: Option<(PathBuf, String)> = None;
        // `Y` or `A` at the question, for this member.
        let mut replace = false;
        // The rule that keeps a file already there without a word (`-o-`,
        // or `E` at the question) asks the filesystem first, one stat, and
        // builds nothing for a member it keeps: 20,000 files all there
        // cost what they did (counted). A file made ahead for the member
        // (`ahead`) would be that file: it goes first.
        #[cfg(all(target_os = "linux", feature = "parallel"))]
        if self.keeps_silently() {
            self.forget_ahead(index);
        }
        #[cfg(all(target_os = "macos", feature = "parallel"))]
        if self.keeps_silently() {
            self.forget_ahead(index);
        }
        if self.keeps_silently() && target.exists() {
            self.done.insert(index);
            self.say_skipping(index, volume, data_end);
            // Kept as it is, so a copy naming it is filled from this
            // member's decode rather than from the file on disk (3.8.5).
            self.note_kept(index);
            return Disposition::Skip;
        }
        loop {
            let target = renamed.as_ref().map_or(target, |(path, _)| path.as_path());
            // The policy next: it reads only the options, and under every
            // other rule the open itself says whether the target is there,
            // so a run that may overwrite, and one that asks, never asks
            // the filesystem with a call of its own. The opener opens
            // nothing that was already there (SPEC-CLI 9.4 W8), so a link
            // at the target cannot redirect the write outside the
            // destination. A name the question has just been answered
            // about is known to be taken, and is not tried again.
            // A SMALL member that replaces a file is held in memory and
            // written in place once it is whole and verified
            // (`output::HOLD_BOUND`). The exclusive create still says
            // whether its name is free: a free name is written as ever.
            let declared = self.plan[index].member.size;
            let small = declared <= output::HOLD_BOUND
                && self.held_declared + declared <= output::hold_total(self.opts.memory_cap);
            if small && replace {
                return self.hold_member(index, target, renamed.clone(), &shown, volume, data_end);
            }
            let policy = if replace {
                crate::safepath::IfOutputExists::Beside
            } else if self.may_overwrite() && !small {
                crate::safepath::IfOutputExists::Replace
            } else {
                crate::safepath::IfOutputExists::Keep
            };
            let (created, staged, decided, form) = self.create_member(index, target, policy);
            match created {
                Ok(Some(crate::safepath::Created {
                    file,
                    beside,
                    in_place,
                })) => {
                    // Written beside a name that is taken: the member's
                    // close gives it the name, or removes it (W7). The
                    // mode it ends with is still the one decided for a
                    // file that was there (`-ai`'s among them), which the
                    // specification leaves as measured.
                    let fresh = beside.is_none() && !in_place;
                    let named = beside.as_ref().map(|_| {
                        let named = crate::safepath::NameAtClose::new(target);
                        self.naming.insert(index, named.clone());
                        named
                    });
                    if let Some(beside) = beside {
                        self.beside.insert(index, beside);
                    }
                    if in_place {
                        self.wrote_in_place = true;
                    }
                    self.note_high_bits(&self.plan[index].member);
                    self.touched = true;
                    let name = renamed.as_ref().map_or(shown.as_str(), |(_, name)| name);
                    self.open_progress(self.mode.verb(), name, volume, data_end);
                    self.open_lines.insert(index);
                    self.wrote.insert(index);
                    // A member opened past the cache has no cursor until it
                    // leaves direct writing (`TimedFile::left_direct`).
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    let behind = match staged {
                        Some(_) => None,
                        None => writeback::Behind::at_open(form == unbuffered::Form::Behind),
                    };
                    let _ = form;
                    let written = Disposition::Write(writer(TimedFile {
                        file,
                        mtime: self.mtime_to_set(&self.plan[index].member),
                        mode: mode::file_finish(decided, fresh),
                        declared: self.plan[index].member.size,
                        written: 0,
                        reserved: 0,
                        staged,
                        shut: false,
                        named,
                        #[cfg(all(target_os = "linux", target_env = "gnu"))]
                        behind,
                    })
                        as Box<dyn Write + Send>);
                    if let Some((path, _)) = renamed {
                        self.target_at[index] = Target::Owned(path);
                    }
                    return written;
                }
                // The path is taken and the rule did not say to write over
                // it: `-o-` (or `E`) keeps it, silently; the default rule
                // asks.
                Ok(None) if small && self.may_overwrite() => {
                    return self.hold_member(
                        index,
                        target,
                        renamed.clone(),
                        &shown,
                        volume,
                        data_end,
                    );
                }
                Ok(None) => {
                    let said = match renamed.as_ref() {
                        Some((_, name)) => name.clone(),
                        None => self.member_display_name(index),
                    };
                    match self.settle_existing(index, target, &said, true) {
                        Standing::Replace => replace = true,
                        Standing::Renamed(path, name) => {
                            self.make_typed_parents(&path);
                            renamed = Some((path, name));
                            replace = false;
                        }
                        Standing::Keep => {
                            self.done.insert(index);
                            self.say_skipping(index, volume, data_end);
                            // Kept as it is, so a copy naming it is filled
                            // from this member's decode rather than from
                            // the file on disk (3.8.5).
                            self.note_kept(index);
                            return Disposition::Skip;
                        }
                        Standing::Stop => {
                            self.done.insert(index);
                            return Disposition::Skip;
                        }
                    }
                }
                Err(err) => {
                    let said = match renamed.as_ref() {
                        Some((_, name)) => name.clone(),
                        None => self.member_display_name(index),
                    };
                    self.refuse_create(index, target, &said, &err);
                    self.say_skipping(index, volume, data_end);
                    return Disposition::Skip;
                }
            }
        }
    }

    /// `-or` for a directory member whose own path holds a file: the
    /// directory made at `path`, the next free numbered name, announced as
    /// `name`, its mode and time queued as for any directory member. The
    /// file is left as it was.
    fn make_numbered_directory(
        &mut self,
        index: usize,
        path: &Path,
        name: &str,
        decided: DirMode,
        left_with: Option<u32>,
    ) -> Disposition<Box<dyn Write + Send>> {
        match mode::create_directory(path, decided) {
            Ok(made) if links::is_real_dir(path) => {
                let left_with = left_with.or(made);
                self.dirs.make(path.to_path_buf());
                self.creating(name);
                let mtime = self.mtime_to_set(&self.plan[index].member);
                if left_with.is_some() || mtime.is_some() {
                    self.dir_finish.push(DirFinish {
                        path: path.to_path_buf(),
                        mode: left_with,
                        mtime,
                    });
                }
                self.done.insert(index);
            }
            made => {
                let err = made
                    .err()
                    .unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists));
                self.refuse_create(index, path, name, &err);
            }
        }
        Disposition::Skip
    }

    /// Opens a small member that REPLACES the file at `target` as one held
    /// in memory (`output::HOLD_BOUND`): its line is opened as a written
    /// member's is, nothing touches the disk, and its close writes it in
    /// place if it is whole ([`Run::write_held`]).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn hold_member(
        &mut self,
        index: usize,
        target: &Path,
        renamed: Option<(PathBuf, String)>,
        shown: &str,
        volume: usize,
        data_end: u64,
    ) -> Disposition<Box<dyn Write + Send>> {
        let member = &self.plan[index].member;
        let decided = self.file_mode(member);
        let mtime = self.mtime_to_set(member);
        let declared = member.size;
        self.note_high_bits(&self.plan[index].member);
        self.touched = true;
        let name = renamed.as_ref().map_or(shown, |(_, name)| name.as_str());
        self.open_progress(self.mode.verb(), name, volume, data_end);
        self.open_lines.insert(index);
        let state = Arc::new(Mutex::new(output::HeldState::Memory(Vec::new())));
        self.held_declared += declared;
        self.held_members.insert(
            index,
            HeldMember {
                declared,
                state: Arc::clone(&state),
                decided,
                mtime,
            },
        );
        // A member that delivers more than it declared leaves the hold
        // for a file beside the name, as a large member has from the
        // start.
        let beside_of = target.to_path_buf();
        let spill: output::Spill = Box::new(move || {
            let made = crate::safepath::make_member_file(
                &beside_of,
                crate::safepath::IfOutputExists::Beside,
                mode::file_create(decided),
            )?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists))?;
            let fresh = made.beside.is_none() && !made.in_place;
            Ok((
                TimedFile {
                    file: made.file,
                    mtime,
                    mode: mode::file_finish(decided, fresh),
                    declared,
                    written: 0,
                    reserved: 0,
                    staged: None,
                    shut: false,
                    named: None,
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    behind: crate::writeback::Behind::at_open(false),
                },
                made.beside,
            ))
        });
        if let Some((path, _)) = renamed {
            self.target_at[index] = Target::Owned(path);
        }
        Disposition::Write(Box::new(output::HeldWriter {
            state,
            file: None,
            spill: Some(spill),
        }) as Box<dyn Write + Send>)
    }

    /// The mode decided for a file member's output. SPEC-CLI 9.4 W3: the
    /// three bits above the nine (set user, set group, sticky) are for the
    /// superuser's run alone; any other run leaves the nine.
    pub(super) fn file_mode(&self, member: &Member) -> FileMode {
        let stored = FileMode::of(member.host, member.attr, self.opts.ignore_attributes);
        if mode::superuser() {
            stored
        } else {
            stored.without_high_bits()
        }
    }

    /// Notes that a member this run WROTE had its high bits left off, for
    /// the one line [`Run::finish`] says about it.
    pub(super) fn note_high_bits(&self, member: &Member) {
        if !mode::superuser()
            && FileMode::of(member.host, member.attr, self.opts.ignore_attributes).has_high_bits()
        {
            self.high_bits_left_off
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Creates a FILE member's output at `target` under `policy`: what the
    /// opener answered, the unbuffered writer's state where the member is
    /// written past the cache, the mode decided for it and the form.
    #[allow(clippy::type_complexity)]
    pub(super) fn create_member(
        &self,
        index: usize,
        target: &Path,
        policy: crate::safepath::IfOutputExists,
    ) -> (
        std::io::Result<Option<crate::safepath::Created>>,
        Option<unbuffered::Staged>,
        FileMode,
        unbuffered::Form,
    ) {
        let member = &self.plan[index].member;
        let decided = self.file_mode(member);
        // A big member is opened PAST THE OS CACHE where the target has
        // such an open ([`unbuffered`]), or written cached with writeback
        // behind the cursor ([`writeback`]). A direct open refused, for any
        // reason, creates the member as every other member is, silently:
        // the opener leaves no file behind from a create it was refused
        // (`safepath::forget_refused_create`), so the cached create below
        // does not find this run's own empty file and take it for one
        // that was already there.
        // What the write rule on facts asks of the member (a knob, off in
        // every shipped build): stored, coded, or coded in a solid archive,
        // which is asked only of a member big enough to be written direct.
        let kind = if member.method == 0 {
            unbuffered::Member::Stored
        } else if member.size >= unbuffered::LEAST && self.volumes.iter().any(|v| v.solid) {
            unbuffered::Member::Solid
        } else {
            unbuffered::Member::Coded
        };
        let form = match target.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            Some(dir) => unbuffered::form_at(member.size, dir, kind, self.opts.memory_cap),
            None => unbuffered::form_at(
                member.size,
                std::path::Path::new("."),
                kind,
                self.opts.memory_cap,
            ),
        };
        // The exclusive create this member's first try makes, made ahead of
        // the walk by a helper (`ahead`): the file at the free name, as the
        // create here would have made it. Anything else, and the walk makes
        // its own create below as before.
        #[cfg(all(target_os = "linux", feature = "parallel"))]
        if policy != crate::safepath::IfOutputExists::Beside && form != unbuffered::Form::Direct {
            if let Some(file) = self.ahead.as_ref().and_then(|ahead| ahead.take(index)) {
                let created = crate::safepath::Created {
                    file,
                    beside: None,
                    in_place: false,
                };
                return (Ok(Some(created)), None, decided, form);
            }
        }
        // macOS: as on Linux, and where no helper made the file the walk
        // makes that same create itself through the helpers' book
        // ([`ahead::Ahead::make_here`]), so the file is closed behind like
        // one made ahead. The create is the one below, call for call: the
        // free name, the exclusive create, the member's mode.
        #[cfg(all(target_os = "macos", feature = "parallel"))]
        if policy == crate::safepath::IfOutputExists::Keep && form != unbuffered::Form::Direct {
            if let Some(ahead) = self.ahead.as_ref() {
                if let Some(file) = ahead.take(index) {
                    let created = crate::safepath::Created {
                        file,
                        beside: None,
                        in_place: false,
                    };
                    return (Ok(Some(created)), None, decided, form);
                }
                if let Some(made) = ahead.make_here(index, target, mode::file_create(decided)) {
                    return (made, None, decided, form);
                }
            }
        }
        let direct = if form == unbuffered::Form::Direct && !unbuffered::open_refused() {
            crate::safepath::make_member_file_with(
                target,
                policy,
                mode::file_create(decided),
                unbuffered::FLAG,
            )
            .ok()
        } else {
            None
        };
        let (created, staged) = match direct {
            // macOS takes the handle past the cache after the open; refused,
            // the member is written cached through the same handle.
            Some(Some(created)) => {
                // The path the open file stands at, which the staging
                // opens again by name when it falls back.
                let at = created.beside.as_deref().unwrap_or(target);
                let staged = unbuffered::take_direct(&created.file)
                    .then(|| unbuffered::Staged::new(at, &created.file, kind));
                (Ok(Some(created)), staged)
            }
            Some(None) => (Ok(None), None),
            None => (
                self.create_cached(target, policy, mode::file_create(decided)),
                None,
            ),
        };
        (created, staged, decided, form)
    }
}

/// A member's writer, built where its file is created ([`Run::begin_member`]):
/// the file itself.
#[cfg(not(all(windows, feature = "parallel")))]
#[inline(always)]
fn writer(file: TimedFile) -> Box<TimedFile> {
    Box::new(file)
}

/// See the other [`writer`]: on Windows the lone write's member is written
/// behind the walk (`lone_write`), and every other member is the file
/// itself.
#[cfg(all(windows, feature = "parallel"))]
fn writer(file: TimedFile) -> Box<dyn Write + Send> {
    super::lone_write::writer(file)
}
