//! What a create prints as it goes: the member lines, the percent and the
//! volume boundaries.

use super::*;

/// The report, shared between the payloads that drive it and the
/// [`Progress`] hook that reports the volume boundaries.
pub(super) type Hook<'a> = std::sync::Arc<std::sync::Mutex<Report<'a>>>;

/// The [`Progress`] side of the same report: the writer hands its volume
/// boundaries here, and the report is the one place the two meet.
pub(super) struct Hooked<'a>(pub(super) Hook<'a>);

impl Progress for Hooked<'_> {
    fn output(&mut self, _total: u64) -> rarkit::Result<()> {
        if let Ok(mut report) = self.0.lock() {
            // The only thing a write report is read for: a member that
            // crossed a volume boundary has its line reopened once the
            // next volume starts taking its bytes. What the figure COUNTS
            // is not read at all, because for a compressed member it
            // counts packed bytes.
            report.resume_after_volume();
        }
        Ok(())
    }

    fn volume_done(&mut self, index: u32) -> rarkit::Result<()> {
        if let Ok(mut report) = self.0.lock() {
            report.volume_closed(index);
        }
        Ok(())
    }

    fn member_started(&mut self, index: usize) -> rarkit::Result<()> {
        if let Ok(mut report) = self.0.lock() {
            report.writer_takes(index);
        }
        Ok(())
    }
}

/// The reference's progress lines, measured rather than guessed.
///
/// Each member's line carries ONE counter, drawn when the line opens,
/// whose value is the percentage the whole operation stands at once that
/// member is complete. A member that runs into the next volume has its
/// counter ERASED on the volume it started in and its result printed on
/// the volume it finishes in, whose line opens with `...` instead of
/// `Adding`. A directory entry gets no counter at all.
///
/// **What drives it.** A member's line opens when its PAYLOAD IS FIRST
/// PULLED, which is the one signal that is the same for every member: the
/// writer's own `Progress::output` reports the bytes it WROTE, and for a
/// compressed member those are packed bytes whose count nothing outside
/// the engine knows in advance. A member with no payload at all - a
/// directory, an empty file - is never pulled, so its line is emitted
/// when the NEXT member's is, or at the end of the run.
pub(super) struct Report<'a> {
    pub(super) out: &'a Out,
    /// Per member: the name to show, its size, whether it is a directory.
    pub(super) members: Vec<(String, u64, bool)>,
    /// Bytes over every member, the counter's denominator.
    pub(super) total: u64,
    /// Per member, the bytes of it and every member before it: the
    /// counter's numerator once that member is complete.
    pub(super) through: Vec<u64>,
    /// The member whose line is open, or the next one to open.
    pub(super) index: usize,
    /// Whether a line is open for `index`.
    pub(super) line_open: bool,
    /// Whether the open line reserved the four column counter field,
    /// which is what decides how its ending walks back.
    pub(super) field_reserved: bool,
    /// Whether `index`'s next line continues it from an earlier volume.
    pub(super) continuing: bool,
    /// A volume closed while a member's line was open, so that line MAY
    /// be cut - the ending is deferred until it is known which.
    ///
    /// It is deferred because the two cases are told apart only by what
    /// happens next, and nothing announces them: a volume that closed
    /// mid-member is followed by more writing, and the LAST volume of a
    /// set closes exactly the same way with nothing after it. Printing
    /// the cut ending eagerly put a `...` line with no result on the end
    /// of every volume set.
    pub(super) cut: bool,
    /// The volume header a new line must print first.
    pub(super) pending_volume: Option<String>,
    /// The volume set's naming, for those headers. `None` for a single
    /// archive, where the writer still reports ONE closed volume at the
    /// end and this report must not read it as a member being cut.
    pub(super) volumes: Option<(String, VolumeNaming, u32)>,
    /// `-idn`: no per-member lines. `-idp`: no counter. `-idq`/`-inul`
    /// silence everything, which [`Out`] already does.
    pub(super) hide_names: bool,
    pub(super) hide_percent: bool,
    /// Whether a member's source refused to open, which ends the write
    /// and is already reported by name.
    pub(super) open_failed: bool,
    /// In a volume set: the member the writer has taken up
    /// (`rarkit::Progress::member_started`) whose source has not been
    /// read yet, so its line opens at that first read.
    pub(super) writer_at: Option<usize>,
    /// In a volume set: per member, whether its source was first read
    /// before the writer took the member up, so its line opens when the
    /// writer does. Empty for a single archive.
    pub(super) read_early: Vec<bool>,
    /// In a volume set: sources that would not open before the writer
    /// took their member up, each with its complaint, which is made when
    /// the writer does.
    pub(super) failed_early: Vec<(usize, String)>,
    /// `-t`: a test follows, and its own banner opens with the newline
    /// that the last member's line would otherwise have ended with.
    ///
    /// Measured: the reference's `-t` run reads
    /// `...  OK \nTesting archive arc.rar\n\n` - ONE newline between the
    /// last result and the banner, where two commands run one after the
    /// other would give two.
    pub(super) test_follows: bool,
    /// `-k`: every file written is locked, and the reference says so
    /// once a file: `Locking archive` after a volume's last line and
    /// before the blank line that opens the next volume's header
    /// (measured). The line for the LAST file, or for a single archive,
    /// is the creator's own, said when it locks.
    pub(super) lock_follows: bool,
}

impl<'a> Report<'a> {
    pub(super) fn new(out: &'a Out, opts: &Options, files: &[Chosen], archive: &str) -> Self {
        Report {
            out,
            members: files
                .iter()
                .map(|file| (file.shown.clone(), file.size, file.is_dir))
                .collect(),
            total: files.iter().map(|file| file.size).sum(),
            through: files
                .iter()
                .scan(0u64, |sum, file| {
                    *sum = sum.saturating_add(file.size);
                    Some(*sum)
                })
                .collect(),
            index: 0,
            line_open: false,
            field_reserved: false,
            continuing: false,
            cut: false,
            pending_volume: None,
            volumes: opts.volume_size.map(|_| {
                (
                    volume_stem(archive),
                    if opts.old_volume_names {
                        VolumeNaming::Classic
                    } else {
                        VolumeNaming::Numbered
                    },
                    estimated_volumes(files, opts),
                )
            }),
            hide_names: opts.shared.hide_names,
            hide_percent: opts.shared.hide_percent,
            open_failed: false,
            writer_at: None,
            read_early: if opts.volume_size.is_some() {
                vec![false; files.len()]
            } else {
                Vec::new()
            },
            failed_early: Vec::new(),
            test_follows: opts.test_after,
            lock_follows: opts.lock_after,
        }
    }

    /// Member `index`'s source has been read for the first time.
    ///
    /// For a single archive that is the member starting, as it always
    /// was. In a VOLUME SET the writer batches small members, so a source
    /// may be read well before the writer reaches its member, and a
    /// volume boundary reported in between would land on the wrong line:
    /// there a member starts once BOTH have happened, this read and the
    /// writer's own word that it has taken the member up
    /// ([`Report::writer_takes`]), which is the moment the line opened
    /// when the writer read each member as it reached it.
    pub(super) fn source_starts(&mut self, index: usize) {
        if self.volumes.is_none() || self.writer_at == Some(index) {
            self.member_starts(index);
        } else if let Some(early) = self.read_early.get_mut(index) {
            *early = true;
        }
    }

    /// Member `index`'s source would not open: said now, or in a volume
    /// set once the writer has taken the member up
    /// ([`Report::source_starts`] says why).
    pub(super) fn source_cannot_open(&mut self, index: usize, err: &std::io::Error) {
        if self.volumes.is_none() || self.writer_at == Some(index) {
            self.cannot_open(index, &unrar::io_reason(err));
        } else {
            self.failed_early.push((index, unrar::io_reason(err)));
        }
    }

    /// The writer has taken up member `index`
    /// (`rarkit::Progress::member_started`). Read only in a volume set.
    pub(super) fn writer_takes(&mut self, index: usize) {
        if self.volumes.is_none() {
            return;
        }
        self.writer_at = Some(index);
        if self.read_early.get(index).copied().unwrap_or(false) {
            self.member_starts(index);
        } else if let Some(at) = self
            .failed_early
            .iter()
            .position(|(member, _)| *member == index)
        {
            let (_, reason) = self.failed_early.swap_remove(at);
            self.cannot_open(index, &reason);
        }
    }

    /// The percentage the operation stands at once member `index` is
    /// complete.
    ///
    /// From the running totals `new` took once. Summed here from the first
    /// member on every call, it was n squared additions over a run, paid
    /// under `-idq` too, since the line is formatted before `Out` drops it:
    /// on 20,000 members 27 to 36 percent of a `-mt1` create's samples
    /// (perf on a Zen 4 rental, the `-hp` work, 30 Sep 2026).
    pub(super) fn percent_at_end_of(&self, index: usize) -> u64 {
        if self.total == 0 {
            return 0;
        }
        (self.through[index].saturating_mul(100) / self.total).min(100)
    }

    /// The writer has begun pulling member `index`.
    pub(super) fn member_starts(&mut self, index: usize) {
        // A member that ended exactly ON a volume boundary is not cut:
        // its result belongs to the volume it ended in.
        self.cut = false;
        if self.line_open {
            self.close_line(Ending::Done);
            self.step();
        }
        // Every member between the last one and this had no payload to
        // pull - a directory, or an empty file - so its whole line is
        // emitted here, in order.
        while self.index < index {
            self.open_line();
            self.close_line(Ending::Done);
            self.step();
        }
        if self.index == index {
            self.open_line();
        }
    }

    /// Moves on to the next member.
    pub(super) fn step(&mut self) {
        self.index += 1;
        self.continuing = false;
    }

    /// A volume has been closed and is complete.
    pub(super) fn volume_closed(&mut self, index: u32) {
        let Some((stem, naming, estimate)) = self.volumes.clone() else {
            // A SINGLE archive is one closed volume too, and its last
            // member's line is still open when the report arrives. Reading
            // that as a member cut in half printed a spurious `...` line
            // for every compressed archive before this guard.
            return;
        };
        if self.line_open {
            self.cut = true;
        }
        let next = index + 1;
        let name = rarkit::volume_file_name(&stem, next, estimate.max(next + 1), naming);
        self.pending_volume = Some(format!("Creating archive {name}"));
    }

    /// The next volume has started taking the cut member's bytes, so the
    /// cut was a real one: the counter is erased and the member's line
    /// opens again on the new volume.
    pub(super) fn resume_after_volume(&mut self) {
        if !self.cut {
            return;
        }
        self.cut = false;
        self.close_line(Ending::Continues);
        self.continuing = true;
        self.open_line();
    }

    /// Opens the line for the current member, printing any volume header
    /// that is waiting first.
    pub(super) fn open_line(&mut self) {
        if self.line_open || self.index >= self.members.len() {
            return;
        }
        if let Some(header) = self.pending_volume.take() {
            if self.lock_follows {
                self.out.say("Locking archive\n");
            }
            self.out.say(&format!("\n{header}\n\n"));
        }
        self.line_open = true;
        if self.hide_names {
            self.field_reserved = false;
            return;
        }
        let (name, _, is_dir) = self.members[self.index].clone();
        // The FIELD is there unless `-idp` gave it up; whether anything
        // is drawn in it is a narrower question, and a directory entry
        // and a continuation line both answer it no.
        let reserved = !self.hide_percent;
        let draw = reserved && !is_dir && !self.continuing;
        let verb = if self.continuing {
            Verb::Continuing
        } else {
            Verb::Adding
        };
        self.out.say(&lines::opening(verb, &name, reserved));
        if draw {
            self.out
                .say(&lines::counter(self.percent_at_end_of(self.index)));
        }
        self.field_reserved = reserved;
    }

    /// Closes the open line, either with the result or by erasing the
    /// counter because the member runs into the next volume.
    pub(super) fn close_line(&mut self, ending: Ending) {
        if !self.line_open {
            return;
        }
        if !self.hide_names {
            let text = lines::ending(ending, self.field_reserved);
            let last = ending == Ending::Done && self.index + 1 == self.members.len();
            if self.test_follows && last {
                self.out.say(text.trim_end_matches('\n'));
            } else {
                self.out.say(&text);
            }
        }
        self.line_open = false;
        self.field_reserved = false;
    }

    /// A member's file would not open, so the write ends here.
    ///
    /// The two lines are the reference's own wording for a source it
    /// cannot read, and they are the same two that a mask matching
    /// nothing already gets from `select`. They go to stderr, where
    /// `-idq` leaves them.
    pub(super) fn cannot_open(&mut self, index: usize, reason: &str) {
        self.open_failed = true;
        let Some(entry) = self.members.get(index) else {
            return;
        };
        self.out
            .complain(&format!("Cannot open {}\n{}", entry.0, reason));
    }

    /// Whether a source refused to open, which the caller reads to answer
    /// with the reference's exit code for that cause rather than a
    /// general one.
    pub(super) fn open_failed(&self) -> bool {
        self.open_failed
    }

    /// Everything still open once the writer has returned: the member it
    /// ended on, and the trailing entries with no payload to pull.
    ///
    /// A volume that closed with a line still open turns out to have been
    /// the LAST volume, so that line ends with its result and not with a
    /// cut.
    ///
    /// `wrote` is whether the writer SUCCEEDED, and a failed write fills
    /// nothing in. The trailing entries are filled because a member with
    /// no payload to pull is never announced any other way; after a
    /// failure they were not written at all, and reporting them `OK` is
    /// how an unreadable file used to be shown as archived before the run
    /// died at the close.
    pub(super) fn finish(&mut self, wrote: bool) {
        self.cut = false;
        self.pending_volume = None;
        if self.line_open {
            self.close_line(Ending::Done);
            self.step();
        }
        if !wrote {
            return;
        }
        while self.index < self.members.len() {
            self.open_line();
            self.close_line(Ending::Done);
            self.step();
        }
    }
}
