//! What a run says: its lines, the slots that keep them in archive order,
//! and the progress figure.

use super::*;

/// Pads `text` out to `column`, or leaves it alone when it is already
/// wider (a very long archived name pushes the trailer right rather than
/// being truncated, which is what the reference does).
pub(super) fn pad_to(text: &str, column: usize) -> String {
    let width = text.chars().count();
    let mut out = text.to_owned();
    if width < column {
        out.push_str(&" ".repeat(column - width));
    }
    out
}

/// Pads `text` out to `column` as [`pad_to`] does, but never leaves fewer
/// than `gap` columns of separation before whatever comes next: when the
/// natural pad to `column` would fall short of `gap` (a name from
/// `column - gap` characters wide up to arbitrarily wider, not only one
/// that already reaches `column`), the reference falls back to exactly
/// `gap` spaces rather than the tighter pad. Measured off the reference
/// on names near and over the listing column, `t` and `x` alike
/// (a file line's five-space gap already shows
/// at real widths four short of the column, not only at or past it).
pub(super) fn separated(text: &str, column: usize, gap: usize) -> String {
    let width = text.chars().count();
    if width + gap <= column {
        pad_to(text, column)
    } else {
        let mut out = text.to_owned();
        out.push_str(&" ".repeat(gap));
        out
    }
}

impl Run<'_> {
    /// A message for the reference's stdout, into this member's slot.
    pub(super) fn say(&mut self, text: &str) {
        // A message the streams would drop is not held in a slot either.
        if !self.streams.says() {
            return;
        }
        if let Some(capture) = self.capture.as_mut() {
            capture.text.push_str(text);
            return;
        }
        match self.emit_to {
            None => self.streams.say(text),
            Some(index) => self.buffer(index, Message::Say(text.to_owned())),
        }
    }

    /// A message for the reference's stderr, into this member's slot.
    pub(super) fn warn(&mut self, text: &str) {
        match self.emit_to {
            None => self.streams.warn(text),
            Some(index) => self.buffer(index, Message::Warn(text.to_owned())),
        }
    }

    /// A per-member complaint on stderr, in the reference's layout.
    pub(super) fn complain(&mut self, name: &str, text: &str) {
        self.warn(&format!("\n{}{text}", pad_to(name, COMPLAINT_COLUMN)));
    }

    pub(super) fn buffer(&mut self, index: usize, message: Message) {
        match self.pending.iter_mut().find(|slot| slot.index == index) {
            Some(slot) => slot.messages.push(message),
            // A slot that has already drained, which nothing here does:
            // the member is still the one being written about, so the
            // message goes out rather than being dropped.
            None => match message {
                Message::Say(text) => self.streams.say(&text),
                Message::Warn(text) => self.streams.warn(&text),
            },
        }
    }

    /// Opens this member's slot and points the output at it.
    pub(super) fn begin_slot(&mut self, index: usize) {
        self.pending.push_back(Pending {
            index,
            messages: Vec::new(),
            settled: false,
        });
        self.emit_to = Some(index);
    }

    /// Points the output at a member whose slot is already open, for the
    /// messages its `close` produces.
    pub(super) fn resume_slot(&mut self, index: usize) {
        self.emit_to = Some(index);
    }

    /// Marks this member finished with, sends the output back to the real
    /// streams and drains every slot at the front that is settled.
    pub(super) fn settle_slot(&mut self, index: usize) {
        if let Some(slot) = self.pending.iter_mut().find(|slot| slot.index == index) {
            slot.settled = true;
        }
        self.emit_to = None;
        self.drain_settled();
    }

    pub(super) fn drain_settled(&mut self) {
        while self.pending.front().is_some_and(|slot| slot.settled) {
            let slot = self.pending.pop_front().expect("a settled front");
            self.write_out(slot);
        }
    }

    /// After a write failed, which ends the run: every member the
    /// concurrent walk had begun whose line has not been said yet is
    /// dropped unsaid, and what this run made for it is removed (kept
    /// under `-kb`, as any unfinished member's file is). The reference
    /// never reached such a member. The member the run stopped on, the
    /// earliest one unfinished, keeps its line: it is the one the write
    /// error names.
    pub(super) fn drop_unsaid(&mut self) {
        let stopped = self
            .passed_over
            .iter()
            .next()
            .or_else(|| self.open_lines.iter().next())
            .copied();
        let mut unsaid: Vec<usize> = self
            .pending
            .iter()
            .filter(|slot| !slot.settled)
            .map(|slot| slot.index)
            .chain(self.held.keys().copied())
            .filter(|index| Some(*index) != stopped)
            .collect();
        unsaid.sort_unstable();
        unsaid.dedup();
        self.pending
            .retain(|slot| slot.settled || Some(slot.index) == stopped);
        for index in unsaid {
            self.discard_failed(index);
            self.drop_held(index);
            self.open_lines.remove(&index);
            self.done.insert(index);
        }
    }

    /// Everything still held, in archive order, whatever its state.
    ///
    /// The abort path: an operation-ending error leaves the members the
    /// walk had run ahead to never closed, and their lines are the run's
    /// account of where it got to. Dropping them would lose output the
    /// sequential path printed.
    pub(super) fn drain_all(&mut self) {
        self.emit_to = None;
        while let Some(slot) = self.pending.pop_front() {
            self.write_out(slot);
        }
    }

    pub(super) fn write_out(&self, slot: Pending) {
        for message in slot.messages {
            match message {
                Message::Say(text) => self.streams.say(&text),
                Message::Warn(text) => self.streams.warn(&text),
            }
        }
    }

    /// The `Extracting from <volume>` banner, once per volume.
    pub(super) fn announce(&mut self, volume: usize) {
        // `p` prints ONE banner, the first `t` would print, and no other.
        // Measured against unrar 7.23 on 30 Sep 2026 (`p -ierr` over RAR 5
        // and rar 4.20 volume sets, stored and compressed, with and without
        // passwords): a member continued into later volumes gets no banner
        // there, and a member selected alone that starts in the third
        // volume gets the banner `t` opens with, the first volume's over a
        // stored set and the third's over a compressed one.
        if self.mode == Mode::Print && !self.announced.is_empty() {
            return;
        }
        if !self.announced.insert(volume) {
            return;
        }
        // With the names hidden (`-idn`) there is no first member line to
        // lead with a blank one, and `x -idn` reads `Extracting from
        // a.rar\n` straight into the counter. Measured against `unrar`
        // 7.23 on 19 Sep 2026; [`Run::finish`] supplies the blank line
        // that such a run does show before its verdict.
        if !self.streams.says() {
            return;
        }
        let gap = if self.opts.hide_names { "" } else { "\n" };
        self.banner_gap_owed = self.opts.hide_names;
        let lead = match self.named_banner.take() {
            Some(named) => {
                self.say(&format!("\n{} {named}\n{gap}", self.mode.banner()));
                ""
            }
            None => "\n",
        };
        self.say(&format!(
            "{lead}{} {}\n{gap}",
            self.mode.banner(),
            self.volume_names[volume]
        ));
    }

    /// A directory line: `Creating    <path>` padded, then `OK`.
    pub(super) fn creating(&mut self, path: &str) {
        // A name, so `-idn` hides it with the member lines.
        if self.opts.hide_names || !self.streams.says() {
            return;
        }
        self.say(&format!(
            "{}OK\n",
            separated(
                &format!("{:VERB_WIDTH$}{path}", "Creating"),
                DIR_NAME_COLUMN,
                2,
            )
        ));
    }

    /// Opens a member's progress line: the verb, the name, the padding
    /// and the percentage the reference reached in this volume.
    pub(super) fn open_progress(&mut self, verb: &str, name: &str, volume: usize, data_end: u64) {
        // The counter is a fraction of the WHOLE SET, not of the volume
        // in hand. Measured on the three-part fixture, where the
        // reference reads 49%, 98% and 100% as it crosses the volumes; a
        // per-volume reading gives 99/99/97 there and 100% for every
        // member of a single archive, and both put the digit count wrong.
        // A quiet run drops the line, so it is not built. Nothing else
        // happens here: the caller keeps the line's open state itself.
        if !self.streams.says() {
            return;
        }
        let reached = data_end.min(self.volume_last_data[volume]);
        let pct = percent(self.volume_offset[volume] + reached, self.total_size);
        let moved = verb != CONTINUED || self.last_pct != Some(pct);
        self.last_pct = Some(pct);
        // A line held for its member's verdict is not said yet: its
        // release (or its refusal) settles the banner's blank line.
        if self.capture.is_none() {
            self.banner_gap_owed = false;
        }
        let names = !self.opts.hide_names;
        let counter = !self.opts.hide_percent;
        let mut text = String::new();
        // A continuation (`...`) takes the `t` and `x` form under `p` too:
        // `...         a.bin`, padded, then the counter, where the first
        // fragment has `p`'s own heading (unrar 7.23, 30 Sep 2026; see
        // `Run::announce` for the sets measured).
        if self.mode == Mode::Print && verb != CONTINUED {
            // `p` heads a member with its own line, then an indented
            // counter that a terminal overwrites in place.
            if names {
                text.push_str(&format!("------ {verb} {name}\n\n"));
            }
            if counter {
                if names {
                    text.push_str("     ");
                }
                text.push_str(&format!("\x08\x08\x08\x08{pct:>3}%"));
            }
        } else if counter {
            if names {
                text.push_str(&separated(
                    &format!("{verb:VERB_WIDTH$}{name}"),
                    FILE_NAME_COLUMN,
                    5,
                ));
            }
            // Four backspaces then the percentage, so a terminal
            // overwrites the tail of the padding exactly as the
            // reference's does.
            if moved {
                text.push_str(&format!("\x08\x08\x08\x08{pct:>3}%"));
            }
        } else if names {
            // Without the counter the line is padded five columns short,
            // where the `  OK ` that follows brings it to the same width
            // as a counted one. A failed member's line stops there. A
            // name too wide to leave that gap gets the same two spaces
            // `creating` separates a directory's `OK` with, rather than
            // running the name into `OK` flush.
            text.push_str(&separated(
                &format!("{verb:VERB_WIDTH$}{name}"),
                FILE_NAME_COLUMN - 5,
                2,
            ));
        }
        self.say(&text);
    }

    /// Say what a member's `open` held back: the engine did not refuse it.
    pub(super) fn release_held(&mut self, index: usize) {
        if let Some(held) = self.held.remove(&index) {
            if let Some(text) = lock(&held.text).take() {
                if !text.is_empty() {
                    self.banner_gap_owed = false;
                }
                self.say(&text);
            }
        }
    }

    /// Drop what a REFUSED member's `open` held back, and remove the
    /// directories it made, deepest first, where nothing else has since
    /// been put in them. Its own file is removed before this is called.
    pub(super) fn drop_held(&mut self, index: usize) {
        let Some(held) = self.held.remove(&index) else {
            return;
        };
        for dir in held.dirs.iter().rev() {
            if fs::remove_dir(dir).is_ok() {
                self.dirs.unmake(dir);
                self.made_modes.remove(dir);
            }
        }
    }

    /// Every line still held, in archive order: the walk ended with these
    /// members open, and their lines are its account of where it got to.
    pub(super) fn release_all_held(&mut self) {
        let mut rest: Vec<usize> = self.held.keys().copied().collect();
        rest.sort_unstable();
        for index in rest {
            self.release_held(index);
        }
    }

    /// Closes an open progress line with the reference's `  OK`, or with
    /// nothing at all when the member failed.
    ///
    /// The switches decide what an `OK` looks like. With the names shown a
    /// member ends its line: `p` writes a newline and the others write
    /// `OK`, over the counter when there is one. With the names hidden a
    /// good member ends nothing, so the counters run together and
    /// [`Run::finish`] ends the last one. A FAILED member's line ends with
    /// a newline in every case, and on stderr for `p`, whose stdout is the
    /// payload.
    pub(super) fn close_progress(&mut self, index: usize, ok: bool) {
        self.close_marked(index, if ok { Mark::Ok } else { Mark::Failed });
    }

    /// [`Run::close_progress`], with the mark a member that did not fail
    /// closes with: `OK`, or the question mark of one nothing vouched for
    /// ([`Mark::Unvouched`]), which sits where the `OK` would and changes
    /// nothing else of the line or the run.
    pub(super) fn close_marked(&mut self, index: usize, mark: Mark) {
        if !self.open_lines.remove(&index) {
            return;
        }
        let ok = mark != Mark::Failed;
        self.last_failed = !ok;
        if !ok {
            if self.mode == Mode::Print {
                // On stderr, and only where the counter it ends went too
                // (`-ierr`): apart, the complaints run on, each opening
                // with its own newline, and ONE newline ends the run
                // ([`Run::finish`]). Measured against unrar 7.23 on 30 Sep
                // 2026: `p` over two damaged members gives `\nb.bin  -
                // checksum error\na.bin  - checksum error\n` on stderr.
                if self.streams.one_stream() {
                    self.warn("\n");
                }
            } else {
                self.say("\n");
            }
        } else if self.opts.hide_names {
            // Nothing: see above.
        } else if self.mode == Mode::Print {
            self.say("\n");
        } else {
            self.say(match (mark, self.opts.hide_percent) {
                (Mark::Unvouched, true) => "   ? \n",
                (Mark::Unvouched, false) => "\x08\x08\x08\x08\x08   ? \n",
                (_, true) => "  OK \n",
                (_, false) => "\x08\x08\x08\x08\x08  OK \n",
            });
        }
    }

    /// Emits the continuation lines for a member that spans volumes, then
    /// closes the line.
    pub(super) fn finish_member(&mut self, index: usize, ok: bool) {
        self.finish_marked(index, if ok { Mark::Ok } else { Mark::Failed });
    }

    /// [`Run::finish_member`], closing with `mark`.
    pub(super) fn finish_marked(&mut self, index: usize, mark: Mark) {
        if !self.open_lines.contains(&index) {
            return;
        }
        self.continue_member(index);
        self.close_marked(index, mark);
    }

    /// The continuation lines of a member that spans volumes, each
    /// volume's `packed data checksum error` line after its own (spec F
    /// 3.5.6), and nothing for a member with one fragment. What closes the
    /// member's line, its `OK` or its complaint, comes after all of them:
    /// measured against unrar 7.23 on 30 Sep 2026, a split member whose
    /// whole checksum fails says `<name> - checksum error` after its LAST
    /// volume's line, not its first.
    pub(super) fn continue_member(&mut self, index: usize) {
        if !self.open_lines.contains(&index) {
            return;
        }
        // Only a member that spans volumes has continuation lines, and
        // only one of those pays for the copies the loop needs (its body
        // borrows `self` mutably), so an unsplit member clones nothing.
        if self.plan[index].fragments.len() > 1 {
            let fragments = self.plan[index].fragments.clone();
            // Only the FIRST line of a member carries the destination the
            // caller typed; a continuation names the archived member alone,
            // and so does the checksum line.
            let name = self.plan[index].member.name.clone();
            self.fragment_line(index, fragments[0].0, &name);
            for (volume, data_end) in fragments.iter().skip(1) {
                // The line ends before the next volume's banner and before
                // a `...` line. `p -idn` has neither, and its counters run
                // on across the volumes (measured against unrar 7.23 on 30
                // Sep 2026: `\x08\x08\x08\x08 32%\x08\x08\x08\x08 64%...`).
                if !(self.mode == Mode::Print && self.opts.hide_names) {
                    self.say("\n");
                }
                self.announce(*volume);
                self.open_progress(CONTINUED, &name, *volume, *data_end);
                self.fragment_line(index, *volume, &name);
            }
        }
    }

    /// Whether a member before `index` whose line is still open continues
    /// into `volume`, so that its continuation, not this member, says the
    /// volume's banner.
    pub(super) fn continued_into(&self, index: usize, volume: usize) -> bool {
        volume > 0
            && !self.announced.contains(&volume)
            && self.open_lines.range(..index).any(|&earlier| {
                self.plan[earlier]
                    .fragments
                    .iter()
                    .skip(1)
                    .any(|&(v, _)| v == volume)
            })
    }

    /// `<name> : packed data checksum error in volume <volume>` on stderr,
    /// when the member's fragment in `volume` disagreed with its field
    /// (spec F 3.5.6). Measured against unrar 7.23 on 30 Sep 2026: a
    /// newline, the ARCHIVED name left justified in 20 columns (a longer
    /// one whole), ` : `, and the volume as the banner names it, with no
    /// newline after, under `t` and under `x` into a destination alike.
    pub(super) fn fragment_line(&mut self, index: usize, volume: usize, name: &str) {
        if !self.mismatches.contains(&(index, volume)) {
            return;
        }
        let text = format!(
            "\n{name:<20} : packed data checksum error in volume {}",
            self.volume_names[volume]
        );
        self.warn(&text);
    }

    /// The name as the progress line spells it: the destination as the
    /// caller typed it, then the archived name, or just the base name
    /// under `e`.
    pub(super) fn member_display_name(&self, index: usize) -> String {
        let member = &self.plan[index].member;
        match self.mode {
            Mode::Test | Mode::Print => member.name.to_string(),
            Mode::Extract { .. } => {
                // The name WRITTEN, as the reference prints it: the on-disk
                // name (`disk_name`, so a Unix name's `\` shows as the `\`
                // written, not as a separator), mapped under safepath rule
                // 5 on a Windows host (`outU\a_` for a member `a.`), with
                // the platform's separator, read as the reference reads
                // bytes (`progress_line_name`): a TAB shows as the TAB written,
                // and on Linux an 8-bit RAR 4 name's `\xe9` as the
                // U+FFFE, U+E0E9 the listing shows.
                let (_, name) = self.target_parts(index);
                let shown = match std::str::from_utf8(name) {
                    Ok(text) => {
                        let mapped = crate::safepath::display_name(text);
                        let mapped = if cfg!(windows) {
                            mapped.replace('/', "\\")
                        } else {
                            mapped.into_owned()
                        };
                        super::progress_line_name(mapped.as_bytes())
                    }
                    Err(_) => super::progress_line_name(name),
                };
                format!("{}{shown}", self.dest)
            }
        }
    }
}

/// What closes a member's progress line.
///
/// Measured against unrar 7.23 and rar 7.23 on 10 Oct 2026 (genuine rar
/// 7.23 archives, file headers rewritten to name no checksum; `t`, `x`
/// and `e`, the default width and `-mt1`, stored, compressed, solid and
/// split): a file, an empty file, a file copy or a link whose OWN header
/// names no checksum closes with `   ? ` in the five columns of the
/// `  OK `, over the counter or, under `-idp`, in its place; the run is
/// still `All OK`, exit 0, and the member is written whole.
/// `tests/no_checksum_member_mark.rs` holds the rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mark {
    /// The member's bytes matched the checksum its header names.
    Ok,
    /// The header names no checksum, so nothing was checked
    /// (`rarkit::MemberOutcome::checksum_ok` is `None`): never `OK`.
    Unvouched,
    /// The member failed: the line ends with no mark.
    Failed,
}

impl Mark {
    /// The mark of a member that did not fail, from the engine's verdict.
    pub(super) fn of(outcome: &rarkit::MemberOutcome) -> Self {
        match outcome.checksum_ok {
            Some(true) => Self::Ok,
            None => Self::Unvouched,
            Some(false) => Self::Failed,
        }
    }
}

/// One buffered message, and which stream it belongs to.
///
/// The two streams are kept apart rather than concatenated: `-ierr` moves
/// one of them and `-idq` silences one of them, so a message has to reach
/// [`Out`] as the kind it was written as. Within each stream the order is
/// the order it was composed in, which is all the reference's output
/// depends on.
pub(super) enum Message {
    /// [`Out::say`]: the reference's stdout.
    Say(String),
    /// [`Out::warn`]: the reference's stderr.
    Warn(String),
}

/// One member's share of the output, and whether it is finished with.
pub(super) struct Pending {
    /// The plan index, so the queue can be drained by archive order and
    /// checked rather than trusted.
    pub(super) index: usize,
    pub(super) messages: Vec<Message>,
    /// Set when the member has been closed (or was never accepted), which
    /// is what lets the slot leave the queue.
    pub(super) settled: bool,
}
