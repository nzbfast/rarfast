//! How a run ends: a member's failure recorded and said, the refusals, and
//! the summary.

use super::*;

/// What a run says, once, when a file that stood at a member's name was
/// written in place because its directory let no file be made beside it.
/// The words are rarfast's own.
const WRITTEN_IN_PLACE: &str = "A file in a directory that may not be written to was written in \
     place: had its member failed, the file that was there would not have been kept";

impl Run<'_> {
    /// Records why a member failed and says so on stderr the way the
    /// reference does.
    pub(super) fn record_failure(&mut self, index: usize) {
        let member = self.plan[index].member.clone();
        // An encrypted member whose bytes do not check out is DAMAGE when
        // its password check record passed: the wrong password never gets
        // this far (spec K 3.7.3). Without a record, nothing can tell the
        // two apart, and the reference says both. Measured against unrar
        // 7.23 on 29 Sep 2026, one flipped byte, stored and compressed,
        // one volume and several, in the first and in the last fragment,
        // `t`, `x` and `p`: a RAR 5 member with a record gives `<name> -
        // checksum error`, exit 3; a RAR 4 member, and a RAR 5 member
        // whose record was removed, give `Checksum error in the encrypted
        // file <name>. Corrupt file or wrong password.`, exit 3, for a
        // wrong password too. `-kb` keeps the file in both.
        let failure = if member.encrypted && !member.password_checked {
            Failure::EncryptedChecksum
        } else {
            Failure::Checksum
        };
        self.errors += 1;
        self.failures.push((index, failure));
        // A member that spans volumes says its later volumes' lines first:
        // the complaint follows the LAST of them (`continue_member`).
        self.continue_member(index);
        // The line the reference had open for this member is closed with
        // no `OK`, and the file it was writing is removed unless `-kb`
        // asked for it.
        if failure == Failure::EncryptedChecksum {
            self.warn(&format!(
                "\nChecksum error in the encrypted file {}. Corrupt file or wrong password.",
                member.name
            ));
        } else {
            self.complain(&member.name, "- checksum error");
        }
        // The complaint comes BEFORE the newline that ends the line, and
        // the order shows once both go to one stream (`-ierr`): the
        // reference's complaint opens with its own newline, so the counter
        // it interrupts has none of its own.
        self.close_progress(index, false);
        // Either failure keeps its file on `-kb`, as the reference does.
        self.discard_failed(index);
        self.done.insert(index);
    }

    /// Closes a member the engine refused for its password
    /// (`MemberOutcome::password_refused`): the reference's `Incorrect
    /// password for <name>`, counted once, then the line ends with no `OK`
    /// and the file is removed, `-kb` or not, because the reference writes
    /// nothing for it. The walk then ends with the same error, which
    /// `report_walk_error` finds already said and does not say again:
    /// saying it at both made `Total errors: 2` of the reference's 1 and,
    /// in `p`, put the line's end before the complaint.
    ///
    /// Measured against unrar 7.23 on 30 Sep 2026 (`t`, `x`, `p`, one
    /// archive and volume sets, stored and compressed, `-ierr` and not):
    /// the reference prints NO progress line for such a member (its held
    /// line is dropped here, [`Run::held`]) and says `Incorrect password
    /// for <name>` once for EVERY volume the member spans, each after that
    /// volume's banner (`p` prints no later banner), counting each in
    /// `Total errors`.
    pub(super) fn close_refused_password(&mut self, index: usize) {
        let name = self.plan[index].member.name.clone();
        self.open_lines.remove(&index);
        let volumes: Vec<usize> = self.plan[index]
            .fragments
            .iter()
            .map(|&(volume, _)| volume)
            .collect();
        for (at, volume) in volumes.into_iter().enumerate() {
            if at > 0 && self.mode != Mode::Print {
                self.announce(volume);
            }
            if std::mem::take(&mut self.banner_gap_owed) {
                self.say("\n");
            }
            // A line of its own: on one stream (`-ierr`) it ends itself,
            // since no progress line is open for it to end.
            if self.streams.one_stream() {
                self.warn(&format!("Incorrect password for {name}\n"));
            } else {
                self.warn(&format!("\nIncorrect password for {name}"));
            }
            self.errors += 1;
        }
        // No counter line is left open for `finish` to end under `-idn`.
        self.last_failed = true;
        self.failures.push((index, Failure::Password));
        self.discard_written(index);
        self.drop_held(index);
        self.done.insert(index);
    }

    /// Removes a failed member's output file, if and only if this run
    /// created it (see [`Run::wrote`]). Outside `x` and `e` nothing was
    /// written, so nothing is removed.
    pub(super) fn discard_written(&mut self, index: usize) {
        // Held in memory and never written: its bytes go, and nothing on
        // the disk was touched.
        self.adopt_spill(index);
        if self.take_held(index).is_some() {
            return;
        }
        if !matches!(self.mode, Mode::Extract { .. }) || !self.wrote.remove(&index) {
            return;
        }
        // Written beside a taken name: the file beside goes, and what
        // stands at the name is as it was (SPEC-CLI 9.4 W7).
        if self.drop_beside(index) {
            return;
        }
        if let Some(target) = self.member_target(index) {
            let _ = fs::remove_file(target);
        }
    }

    /// Removes the file member `index` was being written to BESIDE a taken
    /// name, where there is one; `false` where the member was written at
    /// its own name.
    pub(super) fn drop_beside(&mut self, index: usize) -> bool {
        self.naming.remove(&index);
        match self.beside.remove(&index) {
            Some(beside) => {
                let _ = fs::remove_file(beside);
                true
            }
            None => false,
        }
    }

    /// A failed member's file: removed, unless `-kb` keeps it.
    ///
    /// `-kb` over a member that was being written beside a taken name
    /// keeps the broken NEW file under the member's name, as the
    /// reference keeps it (SPEC-CLI 9.3 O15): the part takes the name,
    /// and what stood there goes, by the switch's own asking. Without
    /// `-kb` the part goes and what stood at the name is as it was (W7).
    /// Either way no name of this program's own is left.
    pub(super) fn discard_failed(&mut self, index: usize) {
        if self.opts.keep_broken {
            // A held member's broken bytes are written now, as `-kb`
            // asks, over the old file.
            let _ = self.settle_name(index);
            return;
        }
        self.discard_written(index);
    }

    /// Takes member `index` out of the hold, and what it declared out of
    /// the count.
    fn take_held(&mut self, index: usize) -> Option<HeldMember> {
        let held = self.held_members.remove(&index)?;
        self.held_declared = self.held_declared.saturating_sub(held.declared);
        Some(held)
    }

    /// A held member that outgrew its bound went to a file
    /// (`output::HeldState::Spilled`): from here on it is a member this
    /// run wrote, beside the taken name where a file could be made
    /// there.
    fn adopt_spill(&mut self, index: usize) {
        let spilled = match self.held_members.get(&index) {
            Some(held) => match &*sink::lock(&held.state) {
                output::HeldState::Spilled(beside) => Some(beside.clone()),
                output::HeldState::Memory(_) => None,
            },
            None => None,
        };
        if let Some(beside) = spilled {
            self.take_held(index);
            self.wrote.insert(index);
            if let Some(beside) = beside {
                self.beside.insert(index, beside);
            }
        }
    }

    /// The member closing as `index` is whole (or broken and kept by
    /// `-kb`): what it was written to takes its name. A member held in
    /// memory is written now if its close has not written it already
    /// ([`Run::write_held`]); one written beside a taken name is renamed
    /// ([`Run::take_name`]); any other owes nothing. The error is that
    /// the member could not have its name: the system's reason.
    pub(super) fn settle_name(&mut self, index: usize) -> std::io::Result<()> {
        self.adopt_spill(index);
        if self.held_members.contains_key(&index) {
            // A write the system refuses here is the caller's to pass
            // over (`-kb` after a member that already failed).
            self.write_held(index)?;
        }
        if let Some(refused) = self.held_refused.remove(&index) {
            return Err(refused);
        }
        self.take_name(index)
    }

    /// Writes a member held in memory over the file that stands at its
    /// name, IN PLACE: the open (which on Windows does not empty a plain
    /// old file: the bytes go over it from offset 0, and an old file longer
    /// than the member is cut to its length after them), the bytes, the
    /// member's bits and time on the open file, the close. Where the old
    /// file cannot be opened so (a link stands there, or its owner may
    /// not read it, or it is gone) the bytes go to a file beside and take
    /// the name by a rename, as a large member's do.
    ///
    /// `Err` is a WRITE the system refused part way (a full volume), and
    /// only that: the caller ends the run as any failed write does (the
    /// reference's `Write error in the file`, exit 5), and the part
    /// written is this run's to remove. A name that could not be HAD (no
    /// file could be opened or made, the rename was refused) is kept for
    /// [`Run::settle_name`], which reports it as a create that failed.
    pub(super) fn write_held(&mut self, index: usize) -> std::io::Result<()> {
        let Some(held) = self.take_held(index) else {
            return Ok(());
        };
        let bytes = match &mut *sink::lock(&held.state) {
            output::HeldState::Memory(bytes) => std::mem::take(bytes),
            output::HeldState::Spilled(_) => return Ok(()),
        };
        let Some(target) = self.member_target(index).map(Path::to_path_buf) else {
            self.held_refused
                .insert(index, std::io::Error::from(std::io::ErrorKind::NotFound));
            return Ok(());
        };
        // The whole length is known before the open: on Windows the file
        // standing at the name is not emptied first, and is cut after the
        // write only where it was longer (`safepath::write_in_place_sized`).
        let len = bytes.len() as u64;
        let opened = match crate::safepath::write_in_place_sized(&target, 0, len) {
            Ok((file, longer)) => {
                #[cfg(feature = "h2-probes")]
                crate::safepath::say_in_place("held");
                Ok((file, None, false, longer))
            }
            Err(_) => crate::safepath::make_member_file(
                &target,
                crate::safepath::IfOutputExists::Replace,
                mode::file_create(held.decided),
            )
            .and_then(|made| {
                made.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists))
            })
            .map(|made| {
                let fresh = made.beside.is_none() && !made.in_place;
                (made.file, made.beside, fresh, false)
            }),
        };
        let (file, beside, fresh, longer) = match opened {
            Ok(opened) => opened,
            Err(refused) => {
                self.held_refused.insert(index, refused);
                return Ok(());
            }
        };
        let mut out = TimedFile {
            file,
            mtime: held.mtime,
            mode: mode::file_finish(held.decided, fresh),
            declared: bytes.len() as u64,
            written: 0,
            reserved: 0,
            staged: None,
            shut: false,
            named: None,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            behind: crate::writeback::Behind::at_open(false),
        };
        // Over a longer old file, the cut to the member's length comes after
        // its bytes and before the close sets its bits and time; a cut the
        // system refuses is a refused write, as a write is.
        let written = out
            .write_all(&bytes)
            .and_then(|()| out.flush())
            .and_then(|()| {
                if !longer {
                    return Ok(());
                }
                #[cfg(feature = "h2-probes")]
                crate::safepath::say_in_place("cut");
                out.file.set_len(len)
            });
        drop(out);
        self.wrote.insert(index);
        if let Some(beside) = beside {
            self.beside.insert(index, beside);
        }
        written?;
        if let Err(refused) = self.take_name(index) {
            self.held_refused.insert(index, refused);
        }
        Ok(())
    }

    /// W7's last step for member `index`: the file it was written to
    /// beside a taken name takes the member's name. Nothing for a member
    /// written at its own name. Where the name cannot be had the file
    /// beside is removed and the error is the system's.
    pub(super) fn take_name(&mut self, index: usize) -> std::io::Result<()> {
        let Some(beside) = self.beside.remove(&index) else {
            return Ok(());
        };
        // The file gave itself the name as it closed: nothing is owed.
        if self
            .naming
            .remove(&index)
            .is_some_and(|named| named.given())
        {
            return Ok(());
        }
        let taken = match self.member_target(index) {
            Some(name) => crate::safepath::take_name(&beside, name),
            None => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        };
        if taken.is_err() {
            let _ = fs::remove_file(&beside);
            self.wrote.remove(&index);
        }
        taken
    }

    /// A member that was whole but could not take its name from what
    /// stood there ([`Run::take_name`]): said as a file that cannot be
    /// created is, counted, exit 9; what stood at the name still does.
    pub(super) fn refuse_name(&mut self, index: usize, err: &std::io::Error) {
        let name = self.member_display_name(index);
        let mut text = format!("\nCannot create {name}\n{}", super::io_reason(err));
        // A directory stands at the name: the reference's third line
        // (SPEC-CLI 9.2 O12), as for a create that is refused at once.
        if self.member_target(index).is_some_and(Path::is_dir) {
            text.push_str("\nDirectory with such name already exists");
        }
        self.warn(&text);
        self.errors += 1;
        self.failures.push((index, Failure::Create));
        self.finish_member(index, false);
    }

    /// What the engine stopping means in the dialect's own words.
    ///
    /// rarkit's extraction ends at the first member it cannot finish, where
    /// the reference carries on to the next one. So one walk yields at most
    /// one of these, and the job here is to say WHICH failure it was in the
    /// reference's wording and rank it into the reference's exit code -
    /// never to print a reason of a class the run did not meet. What the
    /// reference would have gone on to report about LATER members is not
    /// invented: the crate README lists the rows that costs.
    pub(super) fn report_walk_error(&mut self, error: &rarkit::Error, lost_volume: bool) {
        use rarkit::ErrorKind;
        // The walk ended at the question about a file already there, by
        // this sink's own word: [`Run::finish`] says so.
        if self.stopped.is_some() {
            self.release_all_held();
            return;
        }
        // A member refused for its window whose line was held
        // ([`Run::open_member`]) is never said: what its `open` said and
        // made is dropped here, before the rest is released.
        let unsaid = matches!(error.kind(), ErrorKind::LimitExceeded { .. })
            .then(|| self.open_lines.iter().next().copied())
            .flatten()
            .filter(|index| self.held.contains_key(index));
        if let Some(index) = unsaid {
            self.drop_held(index);
            self.open_lines.remove(&index);
        }
        self.release_all_held();
        // A member `Sink::close` already charged is not charged twice; this
        // is only about the reason line and the exit class.
        let charged = self.failures.iter().any(|(_, failure)| {
            matches!(
                failure,
                Failure::Refused | Failure::Checksum | Failure::EncryptedChecksum
            )
        });
        // The FIRST line still open in archive order, which is the member
        // the run did not get past. Sequentially there is at most one; the
        // concurrent walk runs ahead of the decode, so at an abort it may
        // hold several and the earliest of them is the one that stopped
        // the run. Falling back to the last member charged with a failure
        // is unchanged: closes arrive in archive order on both paths, so
        // the last one charged is still the furthest the run reached.
        // A member a later close passed over comes before every line
        // still open, and its line is already ended.
        let open = self
            .passed_over
            .iter()
            .next()
            .or_else(|| self.open_lines.iter().next())
            .copied();
        let stopped_on = open.or_else(|| {
            self.failures
                .iter()
                .rev()
                .find(|(index, _)| *index != usize::MAX)
                .map(|(index, _)| *index)
        });
        match error.kind() {
            // A member refused for its password was named and counted at
            // its own close (`Run::close_refused_password`).
            ErrorKind::PasswordRequired | ErrorKind::WrongPassword
                if self.failures.iter().any(|&(index, failure)| {
                    index != usize::MAX && failure == Failure::Password
                }) => {}
            ErrorKind::PasswordRequired | ErrorKind::WrongPassword => {
                // A member that was NOT selected and was refused on the
                // way (a solid RAR 5 chain decodes it all the same) is
                // named by the engine's error. Measured against unrar
                // 7.23, 9 Oct 2026 (`tests/refused_unselected_member.rs`):
                // the reference names such a member, never the archive;
                // and it reads no further than the last member selected,
                // so one that stands AFTER it is no error at all (`All
                // OK`, exit 0, where this said `Incorrect password for
                // <archive>` and exited 11 with every selected member
                // written right).
                let passed = error.member().and_then(|name| {
                    (0..self.plan.len()).find(|&index| {
                        !self.selected.contains(index)
                            && crate::dialect::unrar::as_stored(&self.plan[index].member.name)
                                .as_bytes()
                                == name
                    })
                });
                if let Some(index) = passed {
                    let last = self.selected.len().checked_sub(1);
                    if last.is_none_or(|last| index > self.selected.at(last)) {
                        return;
                    }
                }
                let name = passed.or(stopped_on).map_or_else(
                    || self.volume_names.first().cloned().unwrap_or_default(),
                    |index| self.plan[index].member.name.to_string(),
                );
                self.warn(&format!("\nIncorrect password for {name}"));
                self.errors += 1;
                self.failures.push((usize::MAX, Failure::Password));
            }
            // The set is short of a volume, which `execute` has already
            // reported as `Cannot find volume` and counted (not reported or
            // counted again here: the reference's own `extract-missing-
            // volume` row carries two errors, not three). The member that
            // was writing when the walk ran off the end of what it has is
            // settled HERE, though: its line closes with the reference's
            // own checksum complaint, because the reference's member line
            // and exit class do not distinguish a lost volume from a
            // checksum mismatch (spec item 18), and its file is kept or
            // removed exactly as a real checksum failure's is, on `-kb` -
            // `Sink::close` is never called on this path, so nothing else
            // settles it.
            // The walk reached a later volume of the set that is there and
            // is no RAR archive at all (the chain named it,
            // `volumes::volume_chain`). Measured against unrar 7.23, macOS
            // arm64, 27 Oct 2026 (a four part set whose second part is
            // plain text, `t` and `x`): `ERROR: Bad archive <that volume>`
            // on stderr, `Program aborted` on stdout, exit 13, and no file
            // left for the member that ran into it. Until then this said
            // `no RAR archive here (volume 1)`, counting from 0 and naming
            // no file, and exited 2. The member still open is closed with
            // no `OK` and its file removed by [`Run::finish`].
            ErrorKind::NotAnArchive if error.volume().is_some_and(|volume| volume > 0) => {
                let name = error
                    .volume()
                    .and_then(|volume| self.volume_names.get(volume as usize))
                    .cloned()
                    .unwrap_or_default();
                self.warn(&format!("\nERROR: Bad archive {name}\n"));
                self.errors += 1;
                self.failures.push((usize::MAX, Failure::BadVolume));
            }
            ErrorKind::Truncated | ErrorKind::Corrupt(_) if lost_volume => {
                if let Some(index) = stopped_on {
                    self.settle_cut_member(index);
                }
            }
            // The walk ran out of source, or met a header it cannot step
            // over (spec F 4.1, 4.6). A member still open is the one the
            // cut went through: the reference closes its line with a
            // checksum complaint. Then the damage itself, said ONCE and
            // after the walk by `execute` when the open saw it; said here
            // only when it did not, which is a volume the chain could not
            // open ahead of the walk.
            //
            // A `Truncated` that NAMES a member is that member's decoder
            // asking for more packed bytes than the member has, in an
            // archive that is whole: the member's own close already said
            // `checksum error`, and the reference says nothing more.
            ErrorKind::Truncated => {
                if let Some(index) = open {
                    self.settle_cut_member(index);
                }
                if self.tail.is_none() && error.member().is_none() {
                    self.report_truncation();
                }
            }
            // A comment block standing between blocks that the engine
            // refuses (spec F 3.3.3 B2) is a header the walk stopped at
            // too: the reference counts one error for it and exits 3, so
            // it is said and counted as a corrupt header, never by the
            // engine's own name for it.
            ErrorKind::HeaderChecksum
            | ErrorKind::Corrupt(
                rarkit::Corruption::Header | rarkit::Corruption::CommentOutsideHeader,
            ) if error.member().is_none() => {
                if let Some(index) = open {
                    self.settle_cut_member(index);
                }
                if self.tail.is_none() {
                    self.report_corrupt_header();
                }
            }
            // A member's own bytes did not decode: a damaged LZ, PPMd or
            // filter stream. Its close has already said `checksum error`
            // and charged it, which is all the reference says about such a
            // member (measured against unrar 7.23 on 27 Sep 2026, damaged
            // RAR 5 and RAR 4 streams, solid and not: `<name> - checksum
            // error`, exit 3). The engine's reason is not printed.
            ErrorKind::Corrupt(_) if error.member().is_some() && charged => {}
            ErrorKind::Source(io) => {
                self.warn(&format!("\n{}\n", super::io_reason(io)));
                self.errors += 1;
                self.failures.push((usize::MAX, Failure::ReadFailed));
            }
            // A window above the policy's ceiling (`-mm<size>` stated a
            // budget) is the member's own REFUSAL, and the
            // member the walk stopped on is settled here: its line closes
            // with no `OK`, it is counted, and the file this run created
            // for it is removed. The engine's own words are the reason.
            //
            // Where the member's line was held and never said (`unsaid`),
            // the refusal takes the place of that line in the reference's
            // layout for a member it refuses (unrar 7.23, 28 Sep 2026, the
            // every-refused-member measurement): `\n<reason>` apart,
            // `<reason>\n` after the line before it on one stream.
            ErrorKind::LimitExceeded { .. } if unsaid.is_some() => {
                let index = unsaid.expect("guarded");
                if self.streams.one_stream() {
                    self.warn(&format!("{error}\n"));
                } else {
                    self.warn(&format!("\n{error}"));
                }
                self.refuse_member(index);
            }
            ErrorKind::LimitExceeded { .. } => {
                self.warn(&format!("\n{error}\n"));
                match stopped_on {
                    Some(index) if !charged && self.open_lines.contains(&index) => {
                        self.refuse_member(index);
                    }
                    _ if !charged => {
                        self.errors += 1;
                        self.failures.push((usize::MAX, Failure::Unattributed));
                    }
                    _ => {}
                }
            }
            // The caller's own code failed, and the only code of this
            // dialect's that the walk runs and that can fail is a member's
            // WRITER: `open` and `close` never return an error here. So in
            // `x` and `e` it is a write that failed partway (a full disk, a
            // file size limit), and the member whose line is open is the
            // one being written. Measured against unrar 7.23 on 27 Sep
            // 2026 with a file size limit under one member: `Write error in
            // the file <path>` and a reason line on stderr, no `OK` on the
            // line, exit 5, and the partial file removed unless `-kb`. The
            // reason is the real one; the reference's second line there is
            // an unrelated errno. Its `Program aborted` is not printed: the
            // concurrent walk has already closed, with their own verdicts,
            // members the reference never reached.
            ErrorKind::Caller if matches!(self.mode, Mode::Extract { .. }) && open.is_some() => {
                let index = open.expect("guarded");
                let reason = std::error::Error::source(error).map_or_else(
                    || error.to_string(),
                    |held| {
                        held.downcast_ref::<std::io::Error>()
                            .map_or_else(|| held.to_string(), super::io_reason)
                    },
                );
                let name = self.member_display_name(index);
                // No newline before it, unlike every other complaint: on
                // one stream it follows the member's open line on that
                // line (unrar 7.23, 9 Oct 2026).
                self.warn(&format!("Write error in the file {name}\n{reason}"));
                // The member's line, where it is still open, ends below
                // and ends the complaint with it on one stream. A member
                // a later close passed over has no line left to end.
                if !self.open_lines.contains(&index) && self.streams.one_stream() {
                    self.warn("\n");
                }
                self.errors += 1;
                self.failures.push((index, Failure::WriteFailed));
                self.finish_member(index, false);
                self.discard_failed(index);
                self.done.insert(index);
            }
            // The refusal of a member this run did not select, which the
            // engine returns once the walk has finished (the first refusal
            // in archive order). MEASURED against unrar 7.23 on macOS
            // (an Apple M3 Mac) and Linux (a small x86-64 VPS), 28 Sep 2026: with one
            // RAR 4 member at an unpack version it does not know, `x`, `e`,
            // `t` and `p` of another member, and `x -x<it>`, print nothing
            // about it and exit 0; selected, it is refused with exit 2.
            _ if self.refused_unselected(error) => {}
            // A member whose compression or unpack version the engine does
            // not know, refused alone while the walk went on (spec F 3.2.6
            // and 3.3.5). Every such member this run selected
            // has been named and counted at its own close
            // (`Run::refuse_unknown`); the walk's error is the first of
            // them again, and says nothing new.
            ErrorKind::Unsupported(rarkit::Unsupported::Version(_))
                if self.refusal_named(error) => {}
            // One this dialect's header reading did not foresee, so it had
            // a line and no name at its close: named here, the reference's
            // two errors counted.
            ErrorKind::Unsupported(rarkit::Unsupported::Version(_)) if error.member().is_some() => {
                let name =
                    crate::dialect::unrar::text_from_archive(error.member().unwrap_or_default());
                self.warn(&format!(
                    "\nUnknown method in {name}\nYou may need a newer version of RAR."
                ));
                // The reference's second error for the same member.
                self.errors += 1;
                if !charged {
                    self.errors += 1;
                    self.failures.push((usize::MAX, Failure::Unattributed));
                }
            }
            // A RAR 5 member whose encryption record names a version or
            // a key derivation count the engine does not know
            // (SWEEP3-08OCT-06). Measured against unrar 7.23 on 9 Oct
            // 2026 (`x -psecret`, an archive of eleven members, the
            // fifth's count 25 or its version 1): the other ten are
            // extracted, stderr reads `Unknown encryption method in f:
            // xc25` (`x1` for the version), `Unknown method in <name>`,
            // `You may need a newer version of RAR.`, `Total errors: 3`,
            // exit 2. The engine refuses that member alone at its close,
            // which charged one error; the reference's other two are
            // counted here. Where the record is a LATER fragment's (the
            // error then names its volume) the member was delivered whole
            // from the first fragment's keys, as the reference delivers
            // it: the first line alone, one error, the same exit. The
            // code says which of the two fields it is only by its size: a
            // count is above 24, and no version that high is known.
            ErrorKind::Unsupported(rarkit::Unsupported::Encryption {
                format: rarkit::Format::Rar5,
                code,
            }) if error.member().is_some() => {
                let name =
                    crate::dialect::unrar::text_from_archive(error.member().unwrap_or_default());
                let what = if *code > 24 {
                    format!("xc{code}")
                } else {
                    format!("x{code}")
                };
                if error.volume().is_some() {
                    self.warn(&format!("\nUnknown encryption method in f: {what}"));
                    self.errors += 1;
                    self.failures.push((usize::MAX, Failure::Unattributed));
                } else {
                    self.warn(&format!(
                        "\nUnknown encryption method in f: {what}\nUnknown method in {name}\nYou may need a newer version of RAR."
                    ));
                    self.errors += 2;
                    self.failures.push((usize::MAX, Failure::Refused));
                }
            }
            // Unsupported, corruption, a limit: the engine's own words are
            // the only account of it, and no reference wording covers a
            // refusal the reference never makes.
            //
            // A member the engine refused has already been charged at its
            // close as a checksum failure, which is the only verdict a
            // close carries; the refusal still ranks the run as the fatal
            // error it is, as the reference's own refusal (`Unknown method
            // in`, exit 2) does, without being counted a second time.
            _ => {
                self.warn(&format!("\n{error}\n"));
                if !charged {
                    self.errors += 1;
                    self.failures.push((usize::MAX, Failure::Unattributed));
                } else if matches!(error.kind(), ErrorKind::Unsupported(_)) {
                    self.failures.push((usize::MAX, Failure::Refused));
                }
            }
        }
    }

    /// A member a close for a LATER member passed over, which the engine
    /// will therefore never close (closes arrive in archive order). Its
    /// line ends here, with no `OK`, and its held output is released in
    /// its place, so the members after it print in order; the file this
    /// run created for it goes unless `-kb`. It is counted when the walk's
    /// error is reported, which names it.
    pub(super) fn pass_over(&mut self, index: usize, buffered: bool) {
        if buffered {
            self.resume_slot(index);
        }
        self.finish_member(index, false);
        self.discard_failed(index);
        self.done.insert(index);
        self.passed_over.insert(index);
        if buffered {
            self.settle_slot(index);
        }
    }

    /// Whether the run owes entry `index` a word if the engine never opens
    /// it: it was asked for and nothing has settled it. An older version of
    /// a file is not owed one: the engine shows such a member to no sink
    /// that did not ask for versions.
    pub(super) fn owes(&self, index: usize) -> bool {
        self.selected.contains(index)
            && !self.done.contains(index)
            && self.plan[index].member.version.is_none()
    }

    /// An entry the plan holds and the engine's walk did not open: the
    /// tool's reading of the headers and the engine's differ about this
    /// member, and nothing was written for it. Named and counted, so such
    /// a run never closes with `All OK`; no reference wording covers it.
    pub(super) fn refuse_unopened(&mut self, index: usize) {
        let name = self.plan[index].member.name.clone();
        self.refuse_by_name(&name, "- not reached by the walk, not extracted");
        self.done.insert(index);
    }

    /// A header the engine opened as a member and the plan holds no entry
    /// for, under the ENGINE's name for it: nothing is written for it,
    /// under that name or any other.
    pub(super) fn refuse_unlisted(&mut self, name: &str) {
        self.refuse_by_name(name, "- not a listed member, not extracted");
    }

    fn refuse_by_name(&mut self, name: &str, why: &str) {
        self.complain(name, why);
        if self.streams.one_stream() {
            self.warn("\n");
        }
        self.errors += 1;
        self.failures.push((usize::MAX, Failure::Unattributed));
    }

    /// Whether `error` is the refusal of a member this run did not select:
    /// it names a member this run skipped, and no member it selected.
    ///
    /// Found by the name the error carries. The engine returns a skipped
    /// member's refusal once the walk has finished and tells the sink
    /// nothing else of it (SPEC-API 4.4, a `close` only for a member opened
    /// with `Write` or `Verify`); until 30 Sep 2026 it closed such a member
    /// as refused, and this read the member from that close.
    pub(super) fn refused_unselected(&self, error: &rarkit::Error) -> bool {
        let Some(raw) = error.member() else {
            return false;
        };
        let mut unselected = false;
        for (index, planned) in self.plan.iter().enumerate() {
            let member = &planned.member;
            if raw == member.disk_name()
                || raw == crate::dialect::unrar::as_stored(&member.name).as_bytes()
            {
                if self.selected.contains(index) {
                    return false;
                }
                unselected = true;
            }
        }
        unselected
    }

    /// A member the engine REFUSED: the line is closed without its `OK`
    /// and the member is counted, but no checksum complaint is printed.
    /// The walk's error line names what is missing.
    ///
    /// The file this run created for it is removed EVEN UNDER `-kb`
    /// (a refusal leaves no file behind). `-kb` keeps a BROKEN
    /// file, the bytes a damaged member did produce; a refused member
    /// produced none, so there is nothing broken to keep, only an empty
    /// file that would read as a member extracted.
    pub(super) fn refuse_member(&mut self, index: usize) {
        self.errors += 1;
        self.failures.push((index, Failure::Refused));
        self.finish_member(index, false);
        self.done.insert(index);
        self.discard_written(index);
    }

    /// A member the engine refused for its version (spec F 3.2.6, 3.3.5),
    /// named at its own close, in archive order, however many there are.
    ///
    /// Measured against unrar 7.23 on 28 Sep 2026 over two and three such
    /// members, RAR 5 and RAR 4, among good ones: each gets `Unknown method
    /// in <name>` and `You may need a newer version of RAR.` on stderr,
    /// where its progress line would have been, and counts TWO errors
    /// (`Total errors: 4` for two, 6 for three), exit 2. On separate
    /// streams each message opens with its newline and ends without one,
    /// the reference's own layout; on one stream (`-ierr`) it follows the
    /// line before it, which has already ended here.
    pub(super) fn refuse_unknown(&mut self, index: usize) {
        let name = &self.plan[index].member.name;
        let text = if self.streams.one_stream() {
            format!("Unknown method in {name}\nYou may need a newer version of RAR.\n")
        } else {
            format!("\nUnknown method in {name}\nYou may need a newer version of RAR.")
        };
        self.warn(&text);
        self.errors += 2;
        self.failures.push((index, Failure::Refused));
        self.done.insert(index);
    }

    /// A member the selection does NOT take and the engine will refuse for
    /// its version, met in a SOLID archive with selected members behind it.
    ///
    /// Those members need its bytes: the chain is decoded through it.
    /// Measured against unrar 7.23 on 9 Oct 2026 (five members `a.txt` to
    /// `e.txt` written solid by rar 7.23, `c.txt`'s algorithm version set
    /// to 9; `x` and `t`): asked for `e.txt`, or for `d.txt` and `e.txt`,
    /// the reference says `Unknown method in c.txt` and `You may need a
    /// newer version of RAR.`, opens no line for a member behind it,
    /// writes nothing and exits 2; asked for `a.txt` and `e.txt` it writes
    /// `a.txt` first. Asked for `a.txt` alone it never reaches `c.txt`:
    /// `All OK`, exit 0, and so here, since no selected member is behind.
    ///
    /// Until then the member in front was never named and each member
    /// behind it was opened and reported `- checksum error`, exit 3: the
    /// wrong member blamed, for the wrong reason.
    ///
    /// The refused member is named where it stands, and the selected
    /// members behind it are settled unsaid, so the engine is not asked
    /// for them. Cold: reached only from the skip of a member whose header
    /// names a version the engine does not know.
    #[cold]
    #[inline(never)]
    pub(super) fn chain_stops_at(&mut self, index: usize) {
        if !self.volumes.iter().any(|volume| volume.solid) {
            return;
        }
        let behind: Vec<usize> = self
            .selected
            .iter()
            .copied()
            .filter(|&later| later > index && !self.done.contains(later))
            .collect();
        if behind.is_empty() {
            return;
        }
        let (volume, _) = self.plan[index].fragments[0];
        self.announce(volume);
        self.refuse_unknown(index);
        for later in behind {
            self.done.insert(later);
        }
    }

    /// The first member of a SOLID archive that the engine will refuse
    /// for its version, for a run whose selection matched nothing: the
    /// reference reads the whole chain then, and stops on that member
    /// (unrar 7.23, 9 Oct 2026: `x` and `t` of a name the archive does
    /// not hold say `Unknown method in c.txt`, `No files to extract`,
    /// exit 2).
    pub(super) fn refused_in_a_solid_chain(&self) -> Option<usize> {
        if !self.volumes.iter().any(|volume| volume.solid) {
            return None;
        }
        (0..self.plan.len()).find(|&index| self.plan[index].member.unknown_version)
    }

    /// Whether `error` names a member [`Run::refuse_unknown`] has already
    /// named, which the walk's error then repeats (the engine returns the
    /// first refusal once the walk has finished).
    pub(super) fn refusal_named(&self, error: &rarkit::Error) -> bool {
        let Some(raw) = error.member() else {
            return false;
        };
        self.failures.iter().any(|&(index, failure)| {
            failure == Failure::Refused && index != usize::MAX && {
                let member = &self.plan[index].member;
                member.unknown_version
                    && (raw == member.disk_name()
                        || raw == crate::dialect::unrar::as_stored(&member.name).as_bytes())
            }
        })
    }

    /// Ends stderr with one newline where the stdout messages are dropped
    /// and the complaints ran on unended ([`Run::finish`]).
    pub(super) fn end_muted_stderr(&mut self) {
        if !self.streams.says() && !self.streams.one_stream() {
            self.warn("\n");
        }
    }

    /// The close of a run stopped at the question about a file already
    /// there ([`Run::settle_existing`]), as unrar 7.23 closes it (macOS
    /// and x86-64 Linux, 2 Oct 2026; plain, `-idq`, `-ierr`, `-idn`,
    /// `-idd`):
    ///
    /// - `Q`: `Program aborted` on stdout, exit 255, or the exit of a
    ///   failure counted before it (9 after a create that failed);
    /// - no answer to read: `Read error in the file stdin` on stderr,
    ///   and a reason line, then `Program aborted` after a blank line,
    ///   exit 12. The reference's reason line is the text of whatever error
    ///   number its process last held, which is not the read's: an input
    ///   that simply ended read `Inappropriate ioctl for device` in every
    ///   Linux row but one (`Operation not permitted`, after a create had
    ///   failed) and, on one Mac for the same empty pipe, that or `Value
    ///   too large to be stored in data type`. Here an input that ended
    ///   says [`END_OF_ANSWERS`], the text the creator's own question
    ///   already answers with (`dialect::rar::repair`), and a read that
    ///   FAILED says its own reason;
    /// - `-idq` leaves stderr unended after either, where every other
    ///   failed run ends it.
    pub(super) fn finish_stopped(&mut self, stopped: Stopped) -> Exit {
        if self.opts.hide_names && !self.last_failed {
            self.say("\n");
        }
        let exit = match stopped {
            // 255, unless a member before the question had failed: the
            // run then exits as that failure ranks (exit 9 after a create
            // that failed, measured).
            Stopped::Quit if self.failures.is_empty() => Exit::Interrupted,
            Stopped::Quit => self.worst_failure(false),
            Stopped::NoAnswer(reason) => {
                let reason = reason.unwrap_or_else(|| END_OF_ANSWERS.to_owned());
                let text = format!("Read error in the file stdin\n{reason}");
                if self.streams.one_stream() {
                    self.warn(&format!("{text}\n"));
                } else {
                    self.warn(&text);
                    self.say("\n");
                }
                Exit::ReadFailed
            }
        };
        self.streams.abort();
        exit
    }

    /// The closing line and the exit code.
    pub(super) fn finish(&mut self, lost_volume: bool) -> Exit {
        // SPEC-CLI 9.4 W3: said once a run, however many members it
        // happened to. After a complaint it is laid out as one (stderr is
        // then ended as after any complaint); on a run with none it is a
        // line of its own.
        let mut notes = Vec::new();
        if std::mem::take(self.high_bits_left_off.get_mut()) {
            notes.push(mode::HIGH_BITS_LEFT_OFF);
        }
        // The one case where W7 does not hold, said once a run as well.
        if std::mem::take(&mut self.wrote_in_place) {
            notes.push(WRITTEN_IN_PLACE);
        }
        for text in notes {
            if self.errors > 0 && !self.streams.one_stream() {
                self.warn(&format!("\n{text}"));
            } else {
                self.warn(&format!("{text}\n"));
            }
        }
        // Every line still open, in archive order. Sequentially this is
        // the one member an aborted walk was writing; concurrently it can
        // be the several the walk had run ahead to. None of them was
        // VERIFIED: a walk that ends well has closed every member it
        // opened, on both drivers, so a line open here belongs to a member
        // the engine never closed, and the walk error already reported
        // and counted is the account of why. Each closes with no `OK`, and
        // the file this run created for it is removed unless `-kb` asked
        // to keep broken files, as for any member that failed. Until 27
        // Sep 2026 these closed with `OK`: a write that failed partway
        // (a file size limit under one member) printed `OK` for the member
        // and kept its partial file, on both paths.
        let unsettled = self.open_lines.iter().copied().collect::<Vec<_>>();
        // A write that failed ENDS the run ([`Run::write_failed`]), and a
        // line still open then belongs to a member the concurrent walk
        // had in flight and abandoned: it is said so on its own line.
        let aborted = self.write_failed();
        for &index in &unsettled {
            self.finish_member(index, false);
            self.discard_failed(index);
            self.done.insert(index);
        }
        // No name of this program's own choosing outlives the run
        // (SPEC-CLI 9.4 W7): a file beside a taken name that nothing above
        // settled goes here.
        for (_, beside) in self.beside.drain() {
            let _ = fs::remove_file(beside);
        }
        // Backstop: a member left unverified is never beside `All OK`,
        // whatever did or did not report the reason.
        if (!unsettled.is_empty() || !self.passed_over.is_empty()) && self.errors == 0 {
            self.errors += 1;
            self.failures.push((usize::MAX, Failure::Unattributed));
        }
        if let Some(stopped) = self.stopped.take() {
            return self.finish_stopped(stopped);
        }
        // A volume that is no RAR archive ends the run as the reference
        // ends it: `Program aborted` where a run that went on says `Total
        // errors` (the walk's error arm has the measurement).
        if self
            .failures
            .iter()
            .any(|&(_, failure)| failure == Failure::BadVolume)
        {
            self.streams.abort();
            return self.worst_failure(lost_volume);
        }
        // A failed write is the last thing the reference does: `Program
        // aborted` where a run that went on says `Total errors`, under
        // `-idd` too, and its two lines on stderr end with no newline
        // whether or not stdout is shown (unrar 7.23, 9 Oct 2026, a full
        // volume and a file size limit, `x` and `e`, solid and not, plain,
        // `-idq`, `-idd` and `-ierr`; `tests/write_error_aborts.rs`).
        if aborted {
            // Each member the walk had begun and did not finish, in
            // archive order: its line ended with no `OK` (here, or where
            // a later member's close passed over it) and its partial
            // file is gone. rarfast's own line; the reference has no
            // such member.
            let failed = |index: &usize| {
                self.failures
                    .iter()
                    .any(|&(at, failure)| at == *index && failure == Failure::WriteFailed)
            };
            let mut abandoned: Vec<usize> = unsettled
                .iter()
                .chain(self.passed_over.iter())
                .copied()
                .filter(|index| !failed(index))
                .collect();
            abandoned.sort_unstable();
            abandoned.dedup();
            for index in abandoned {
                let name = self.member_display_name(index);
                self.say(&format!("{name} - not extracted\n"));
            }
            // And stderr is left as the complaint left it, under `-idq`
            // too (`Out::abort`).
            self.streams.abort();
            return self.worst_failure(lost_volume);
        }
        // The blank line `No files to extract` opens with is the banner's
        // own where a member was reached and its banner said.
        let lead = if self.announced.is_empty() || (self.opts.hide_names && !self.last_failed) {
            "\n"
        } else {
            ""
        };
        if !self.touched && self.errors == 0 {
            self.say(&format!("{lead}No files to extract\n"));
            return Exit::NothingMatched;
        }
        // Nothing processed and every member that was reached could not be
        // created: the reference closes with `No files to extract` in place
        // of `Total errors`, exit 9 (unrar 7.23, 2 Oct 2026: `x -o+` over
        // an archive of files only, every one already there with the
        // immutable flag; plain, `-idq`, `-ierr` and `-idd`, which keeps
        // the line).
        if !self.touched
            && !self.failures.is_empty()
            && self
                .failures
                .iter()
                .all(|&(index, failure)| failure == Failure::Create && index != usize::MAX)
        {
            self.end_muted_stderr();
            self.say(&format!("{lead}No files to extract\n"));
            return Exit::CannotCreate;
        }
        // Nothing processed but members refused for their versions, each
        // already named: unrar 7.23 closes with `No files to extract` in
        // place of `Total errors`, exit 2 (28 Sep 2026, `t` and `x` of a
        // RAR 4 member at unpack version 36 alone, and of two RAR 5
        // members at compression version 2), and with no blank line
        // before it, where the line above has one.
        if !self.touched
            && !self.failures.is_empty()
            && self
                .failures
                .iter()
                .all(|&(index, failure)| failure == Failure::Refused && index != usize::MAX)
        {
            // Its stderr ends as after any complaint (below; unrar 7.23,
            // 30 Sep 2026, five RAR 5 members at compression version 2,
            // `t`, `x` and `p`, plain and `-idq`).
            self.end_muted_stderr();
            self.say("No files to extract\n");
            return Exit::Aborted;
        }
        // With the names hidden the counters share one line and a good
        // last member has not ended it; a failed one has.
        if self.opts.hide_names && !self.last_failed {
            self.say("\n");
        }
        // `-idd` drops the closing verdict, `All OK` and `Total errors`
        // alike (measured over a damaged archive as well as a sound one).
        let verdict = !self.opts.hide_done;
        if self.errors == 0 {
            if verdict {
                self.say("All OK\n");
            }
            return Exit::Clean;
        }
        // Where the stdout messages are dropped, `p` (its stdout is the
        // payload) and `-idq`: the complaints on stderr each opened with a
        // newline and none ended with one, so the run ends that stream with
        // one newline, under `-idd` too (unrar 7.23, 30 Sep 2026: `p` over
        // damaged and refused members; `t` and `x -idq` over a refused
        // password in every volume of a set, over a rar 4.20 `-hp` archive
        // with a damaged later header, and, as the every-refused-member
        // measurement recorded, over refused versions and checksum complaints;
        // `-inul` silences it, as `warn` does).
        self.end_muted_stderr();
        if verdict {
            self.say(&format!("Total errors: {}\n", self.errors));
        }
        self.worst_failure(lost_volume)
    }

    /// Whether a member's write failed, which ends the run.
    ///
    /// The reference stops at the first failed write: nothing after that
    /// member is touched. At one thread (`-mt1`) so does this, exactly.
    /// Wider, the walk has later members in flight when the write fails:
    /// the ones already written whole stay, each with its `OK` (a right,
    /// complete file is never deleted), and one that was still being
    /// written is abandoned and named `<name> - not extracted` before the
    /// closing line ([`Run::finish`]). A NAMED DIFFERENCE,
    /// kept on purpose (9 Oct 2026), and with it that `-kb` keeps the bytes
    /// of the failed member that fitted where the reference keeps none.
    fn write_failed(&self) -> bool {
        self.failures
            .iter()
            .any(|&(_, failure)| failure == Failure::WriteFailed)
    }

    /// The exit code of a run that counted an error: the worst of its
    /// failures, as the reference ranks them.
    pub(super) fn worst_failure(&self, lost_volume: bool) -> Exit {
        let mut worst = if lost_volume {
            Exit::CannotOpen
        } else {
            Exit::Clean
        };
        for (_, failure) in &self.failures {
            worst = worst.worse_of(match failure {
                Failure::Checksum | Failure::EncryptedChecksum => Exit::ChecksumMismatch,
                Failure::Password => Exit::WrongPassword,
                Failure::LostVolume => Exit::CannotOpen,
                // A cut archive on its own is unrar's warning, and it
                // ranks below the checksum failure the cut member also
                // reports - which is what `t` over the truncated fixture
                // comes back as.
                Failure::Truncated => Exit::Cautioned,
                Failure::CorruptHeader => Exit::ChecksumMismatch,
                // No captured reference row covers a refused name, so
                // this is a judgement: report it as fatal rather than
                // let a hostile archive finish quietly.
                Failure::LeavesDestination => Exit::Aborted,
                Failure::Create => Exit::CannotCreate,
                Failure::UnsafeLink => Exit::Cautioned,
                Failure::CopySource => Exit::CannotOpen,
                Failure::ReadFailed => Exit::ReadFailed,
                Failure::WriteFailed => Exit::WriteFailed,
                Failure::Unattributed | Failure::Refused => Exit::Aborted,
                Failure::BadVolume => Exit::NotAnArchive,
            });
        }
        // Backstop: a counted error must never leave the run exiting 0.
        if worst == Exit::Clean {
            worst = Exit::Aborted;
        }
        worst
    }
}
