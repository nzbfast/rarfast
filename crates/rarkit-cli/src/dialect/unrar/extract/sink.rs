//! The sinks the engine writes through: the sequential one and the
//! pool's, and what an encrypted member's open holds back.

use super::*;

/// The bookkeeping both sinks share: which plan entry a callback is about.
///
/// **A callback is tied to its entry by what the ENGINE says it opened,
/// never by a count.** Until 8 Oct 2026 the n-th `open` was given the n-th
/// entry of the plan, on the reading that the engine opens once per member
/// in the order [`build_plan`] folded the headers into. Where the two
/// differed by one header (a continuation block written twice, a stray
/// "split before" header, one cleared "split after" bit, a file version the
/// engine does not show) every later member's bytes were written to, and
/// called `OK` under, a neighbouring member's name. So:
///
/// - `open` finds its entry by where the engine says the member's data
///   ends in its volume ([`Walk::locate`]), going forward from the entry
///   after the last one opened, and no further than the volume the engine
///   was last handed (`entered`);
/// - a header the engine opens that says it CONTINUES a member, and is no
///   entry, is passed over: nothing is written and nothing said, as unrar
///   7.23 does (see [`build_plan`]);
/// - any other header that is no entry is refused under the engine's own
///   name for it ([`Run::refuse_unlisted`]), and an entry the walk went
///   past without opening is refused under its own
///   ([`Run::refuse_unopened`]). Nothing is guessed.
///
/// `closing` is a QUEUE and not a cursor, and that is the concurrent
/// path's one demand on this bookkeeping: `open` runs ahead of the
/// decode, so by the time a member is closed several later ones have been
/// opened and "the member whose line is open" no longer names one member.
/// Every member `open` accepted is pushed here, and `close` arrives in
/// archive order.
///
/// **But not for every one of them**, so a close is matched to its member
/// by what the engine said of it at its `open` ([`Accepted::closed_by`]),
/// not by position. The engine skips the `close` of a member whose error
/// ends the whole operation (a write that failed, a source that failed),
/// and still closes, with their own verdicts, the members in flight after
/// it (SPEC-API 8.3, "Errors are not lost"). Taking the front then booked
/// each later close against the member before it: found 27 Sep 2026 with a
/// file size limit under one member, where the failed member was reported
/// `OK` and the LAST member, whole, was named in the write error and
/// removed. A member a close passes over stays queued with its line open,
/// and `Run::finish` settles it with no `OK`. When nothing is skipped the
/// front matches first time.
pub(super) struct Walk<'a, 'b> {
    pub(super) run: &'a mut Run<'b>,
    /// The plan entry after the last one the engine opened: where the
    /// next `open` is looked for first.
    pub(super) expect: usize,
    pub(super) closing: VecDeque<Accepted>,
    /// Whether a member's output is held until the member is settled.
    /// Only the concurrent driver needs it; the sequential walk closes
    /// each member before it opens the next, so its output is already in
    /// archive order and holding it would only add a copy.
    pub(super) buffered: bool,
    /// The last volume the engine was handed (`engine::OnDemand`). The
    /// header an `open` describes is in that volume or, where the engine
    /// reads ahead of its callbacks, an earlier one: never a later one.
    pub(super) entered: Arc<std::sync::atomic::AtomicUsize>,
    /// Whether the plan's entries are in order of volume and offset, which
    /// a forward walk of the headers makes them: [`Walk::locate`] searches
    /// by halves where they are and one by one where they are not.
    pub(super) ordered: bool,
    /// How many headers were refused as no entry of the plan: each has an
    /// output slot of its own, numbered past the plan's.
    pub(super) unlisted: usize,
}

/// A member `open` accepted, as the ENGINE described it there.
pub(super) struct Accepted {
    pub(super) index: usize,
    /// [`name_key`] of the name the engine opened it under.
    name: u64,
    /// Where its first fragment's data ends.
    data_end: u64,
    /// Whether that fragment said the data continues in the next volume.
    continues: bool,
}

impl Accepted {
    /// Whether the engine's `close` (or fragment report) for `member` is
    /// this member's: the name it was opened under, and either the very
    /// header it was opened at or, for a member that continued, a later
    /// fragment of it. The engine describes a split member by its LAST
    /// fragment at its close.
    fn closed_by(&self, member: &rarkit::MemberInfo<'_>) -> bool {
        self.name == name_key(member.name)
            && (self.data_end == member.data.end || (self.continues && member.split_before))
    }
}

/// A name as the engine gives it, reduced to a key: an `open` and its
/// `close` are compared engine to engine, with no copy of the name kept.
fn name_key(name: &[u8]) -> u64 {
    use std::hash::Hasher as _;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(name);
    hasher.finish()
}

/// What the header of an `open` is to the plan.
enum Opening {
    /// The head of this entry.
    Member(usize),
    /// A header that continues a member and is no entry: passed over.
    Continuation,
    /// No header the plan holds as a member.
    Unlisted,
}

impl Walk<'_, '_> {
    /// The plan entry whose head is the header the engine opened.
    ///
    /// The engine opens the headers it reaches in archive order, so the
    /// header of this `open` is the first one, from `expect` on, whose data
    /// ends where the engine says this member's does; an entry in front of
    /// it that does not is one the engine did not open. Offsets repeat
    /// from volume to volume, so the search goes volume by volume and stops
    /// at the last one the engine was handed.
    fn locate(&self, member: &rarkit::MemberInfo<'_>) -> Opening {
        let plan = &self.run.plan;
        let fits = |planned: &Planned| {
            planned.fragments[0].1 == member.data.end
                && planned.member.split_before == member.split_before
                && planned.member.is_dir == member.is_directory
                && planned.member.size == member.unpacked_size.unwrap_or(0)
        };
        let entered = self.entered.load(std::sync::atomic::Ordering::Relaxed);
        let Some(next) = plan.get(self.expect) else {
            return self.no_entry(member);
        };
        if fits(next) && next.fragments[0].0 <= entered {
            return Opening::Member(self.expect);
        }
        // The one "split before" entry is the plan's first, where it has one.
        if member.split_before {
            return Opening::Continuation;
        }
        let rest = &plan[self.expect..];
        let found = if self.ordered {
            (next.fragments[0].0..=entered).find_map(|volume| {
                rest.binary_search_by(|planned| {
                    planned.fragments[0].cmp(&(volume, member.data.end))
                })
                .ok()
                .filter(|&at| fits(&rest[at]))
            })
        } else {
            rest.iter()
                .position(|planned| planned.fragments[0].0 <= entered && fits(planned))
        };
        match found {
            Some(at) => Opening::Member(self.expect + at),
            None => self.no_entry(member),
        }
    }

    fn no_entry(&self, member: &rarkit::MemberInfo<'_>) -> Opening {
        if member.split_before {
            Opening::Continuation
        } else {
            Opening::Unlisted
        }
    }

    pub(super) fn on_open(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
    ) -> Disposition<Box<dyn Write + Send>> {
        let index = match self.locate(member) {
            Opening::Member(index) => index,
            Opening::Continuation => return Disposition::Skip,
            Opening::Unlisted => {
                let slot = self.run.plan.len() + self.unlisted;
                self.unlisted += 1;
                if self.buffered {
                    self.run.begin_slot(slot);
                }
                self.run
                    .refuse_unlisted(&crate::dialect::unrar::text_from_archive(member.name));
                if self.buffered {
                    self.run.settle_slot(slot);
                }
                return Disposition::Skip;
            }
        };
        // The entries the walk went past: the engine did not open them.
        for passed in self.expect..index {
            if self.run.owes(passed) {
                if self.buffered {
                    self.run.begin_slot(passed);
                }
                self.run.refuse_unopened(passed);
                if self.buffered {
                    self.run.settle_slot(passed);
                }
            }
        }
        self.expect = index + 1;
        self.run.reached = self.expect;
        if self.buffered {
            self.run.begin_slot(index);
        }
        // A dictionary above the policy's window may be refused after this
        // `open`; a smaller one never is for its window.
        self.run.note_width(member);
        let over_window = member
            .dictionary
            .is_some_and(|dictionary| dictionary > self.run.window_ceiling);
        let disposition =
            self.run
                .begin_member(index, member.is_directory, member.redirection, over_window);
        // Every entry before `expect` is opened, its directories made.
        #[cfg(all(target_os = "linux", feature = "parallel"))]
        if let Some(ahead) = self.run.ahead.as_ref() {
            ahead.walked(self.expect);
        }
        #[cfg(all(target_os = "macos", feature = "parallel"))]
        if let Some(ahead) = self.run.ahead.as_ref() {
            ahead.walked(self.expect);
        }
        if matches!(disposition, Disposition::Skip) {
            // No `close` will come for it (SPEC-API 4.4), so its slot is
            // finished with the moment `open` returns.
            if self.buffered {
                self.run.settle_slot(index);
            }
        } else {
            self.closing.push_back(Accepted {
                index,
                name: name_key(member.name),
                data_end: member.data.end,
                continues: member.split_after,
            });
            self.run.emit_to = None;
        }
        disposition
    }

    /// A leading fragment of the member closing next disagreed with its
    /// field (spec F 3.5.6): kept for the member's close, which says it
    /// where that volume's line ends.
    pub(super) fn on_fragment_mismatch(&mut self, member: &rarkit::MemberInfo<'_>, volume: u32) {
        let volume = volume as usize;
        let plan = &self.run.plan;
        let found = self.closing.iter().find(|accepted| {
            accepted.name == name_key(member.name)
                && plan[accepted.index]
                    .fragments
                    .iter()
                    .any(|&(at, _)| at == volume)
        });
        if let Some(accepted) = found {
            self.run.mismatches.push((accepted.index, volume));
        }
    }

    pub(super) fn on_close(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
        out: Option<Box<dyn Write + Send>>,
        outcome: &rarkit::MemberOutcome,
    ) -> std::io::Result<()> {
        // A written member's file is flushed BEFORE its verdict: a big
        // member written past the OS cache holds its last staged block
        // until then (`TimedFile::flush`), and a tail that cannot be
        // written is a write error, not a member whose checksum the engine
        // found right over bytes that reached no disk. The error ends the
        // walk as a failed write does: the member stays queued with its
        // line open, and `Run::report_walk_error` names it. `p` writes to
        // standard output, which is not flushed here.
        //
        // The file handle is dropped before the line is closed either way,
        // so `TimedFile`'s mtime restore has happened by the time anything
        // else looks at the path.
        if let Some(mut out) = out {
            if matches!(self.run.mode, Mode::Extract { .. }) {
                out.flush()?;
                // Whole and verified, and its file still open: a member
                // written beside a taken name takes the name as the file
                // closes, here (SPEC-CLI 9.4 W7).
                if !outcome.password_refused && outcome.checksum_ok != Some(false) {
                    let closing = self
                        .closing
                        .iter()
                        .find(|accepted| accepted.closed_by(member));
                    if let Some(accepted) = closing {
                        let index = accepted.index;
                        self.run.arm_name(index);
                        // A member held in memory is written now, in
                        // place. A write the system refuses is this
                        // call's error, as a flush that fails is: it ends
                        // the walk as a failed write does.
                        self.run.write_held(index)?;
                    }
                }
            }
            // A file made ahead is closed behind (`ahead`): nothing reads
            // it by name before the walk ends but the removal of a failed
            // member, which a later close does not disturb.
            #[cfg(all(target_os = "linux", feature = "parallel"))]
            let out = self.close_behind(member, out);
            #[cfg(all(target_os = "macos", feature = "parallel"))]
            let out = self.close_behind(member, out);
            drop(out);
        }
        // Every close is of a member `open` accepted (the engine closes no
        // member this run skipped, SPEC-API 4.4); one that matches nothing
        // queued is left alone rather than taken as the front's.
        let Some(at) = self
            .closing
            .iter()
            .position(|accepted| accepted.closed_by(member))
        else {
            return Ok(());
        };
        for skipped in self.closing.drain(..at).collect::<Vec<_>>() {
            self.run.pass_over(skipped.index, self.buffered);
        }
        let Some(Accepted { index, .. }) = self.closing.pop_front() else {
            return Ok(());
        };
        if self.buffered {
            self.run.resume_slot(index);
        }
        // Not refused: the line held at `open` goes out now, before the
        // member's continuation lines and verdict.
        if !outcome.password_refused {
            self.run.release_held(index);
        }
        // A link, a hard link, a copy, or a copy's target decoded into it.
        if self.run.close_redirect(index, outcome) {
            if self.buffered {
                self.run.settle_slot(index);
            }
            return Ok(());
        }
        // `p` opens no progress line, so it has nothing to close and
        // nothing to charge - which is what the sequential path did by
        // reading its single open line and finding none.
        if self.run.open_lines.contains(&index) && outcome.password_refused {
            // Refused for its PASSWORD before any byte was decoded: the
            // reference's one `Incorrect password` for it is said when the
            // walk ends with that error (`report_walk_error`), and nothing
            // is said here, not a checksum complaint. Where its `open` made
            // directories, nothing made ahead may stand in them when they
            // are removed (`ahead`, `Run::halt_ahead`).
            #[cfg(any(
                all(target_os = "linux", feature = "parallel"),
                all(target_os = "macos", feature = "parallel")
            ))]
            if self
                .run
                .held
                .get(&index)
                .is_some_and(|held| !held.dirs.is_empty())
            {
                self.run.halt_ahead();
            }
            self.run.close_refused_password(index);
        } else if self.run.open_lines.contains(&index) {
            match outcome.checksum_ok {
                // `None` is a member with nothing to check against: its
                // line closes with the reference's question mark, never
                // `OK`, and the run goes on as for a member that passed
                // ([`Mark`]).
                Some(true) | None => {
                    // Whole and verified: a member written beside a taken
                    // name takes the name here, and only here (SPEC-CLI
                    // 9.4 W7). Its file is closed by now, above.
                    match self.run.settle_name(index) {
                        Ok(()) => self.run.finish_marked(index, Mark::of(outcome)),
                        Err(err) => self.run.refuse_name(index, &err),
                    }
                    self.run.done.insert(index);
                }
                // Every member whose bytes did not come out right, however
                // many it produced. Until 28 Sep 2026 a member that
                // produced NONE was taken for one the engine had refused,
                // and got no complaint here and the engine's reason with
                // exit 2 at the end; but a stream damaged near its start
                // (the Huffman tables of an LZ block) also produces none,
                // and for that the reference says `<name> - checksum
                // error` and exits 3, damaged RAR 5 and RAR 4 streams
                // alike. The heuristic dated from an engine whose RAR 5
                // decoder was not wired yet. A real refusal still prints
                // its reason and ranks the run fatal: see
                // `report_walk_error`.
                Some(false) => self.run.record_failure(index),
            }
        } else if self.run.plan[index].member.unknown_version {
            // A member opened with no line because its header names a
            // version the engine does not know (`Run::begin_member`).
            if outcome.checksum_ok == Some(false) {
                self.run.refuse_unknown(index);
            } else {
                // The engine decoded what the header said it would refuse:
                // this dialect's reading of spec F 3.3.5's table has
                // drifted from the engine's. The member's bytes went
                // nowhere, so it is never passed over quietly.
                debug_assert!(false, "member {index} was not refused");
                self.run.record_failure(index);
            }
        }
        if self.buffered {
            self.run.settle_slot(index);
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "parallel"))]
impl Walk<'_, '_> {
    /// `out` handed to the helpers to close, where its file was made ahead
    /// (`ahead`); otherwise given back, for the caller to close.
    fn close_behind(
        &self,
        member: &rarkit::MemberInfo<'_>,
        out: Box<dyn Write + Send>,
    ) -> Option<Box<dyn Write + Send>> {
        let Some(ahead) = self.run.ahead.as_ref() else {
            return Some(out);
        };
        let made = self
            .closing
            .iter()
            .find(|accepted| accepted.closed_by(member))
            .is_some_and(|accepted| ahead.made(accepted.index));
        if made {
            ahead.close_later(out)
        } else {
            Some(out)
        }
    }
}

/// macOS: the same hand over (`ahead`). A file the walk made itself
/// through the helpers' book counts as made ahead
/// ([`ahead::Ahead::make_here`]).
#[cfg(all(target_os = "macos", feature = "parallel"))]
impl Walk<'_, '_> {
    fn close_behind(
        &self,
        member: &rarkit::MemberInfo<'_>,
        out: Box<dyn Write + Send>,
    ) -> Option<Box<dyn Write + Send>> {
        let Some(ahead) = self.run.ahead.as_ref() else {
            return Some(out);
        };
        let made = self
            .closing
            .iter()
            .find(|accepted| accepted.closed_by(member))
            .is_some_and(|accepted| ahead.made(accepted.index));
        if made {
            ahead.close_later(out)
        } else {
            Some(out)
        }
    }
}

/// What an encrypted member's `open` said and made, while it opens.
#[derive(Default)]
pub(super) struct Capture {
    pub(super) text: String,
    pub(super) dirs: Vec<PathBuf>,
}

/// What an encrypted member's `open` said, held until it is known not to
/// be refused (`None` once said), and the directories it made.
pub(super) struct Held {
    pub(super) text: Arc<Mutex<Option<String>>>,
    pub(super) dirs: Vec<PathBuf>,
}

pub(super) fn lock<T>(held: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    held.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `p`'s output for an encrypted member: its held heading is printed before
/// the first byte, so the heading still leads the payload wherever the two
/// streams meet. A refused member writes no byte, and its heading is
/// dropped at its close.
pub(super) struct ReleaseFirst {
    pub(super) inner: Box<dyn Write + Send>,
    pub(super) held: Arc<Mutex<Option<String>>>,
    pub(super) streams: super::Out,
}

impl Write for ReleaseFirst {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(text) = lock(&self.held).take() {
            self.streams.say(&text);
        }
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The dialect's sequential `Sink`: every line the reference prints for a
/// member, and where that member's bytes go.
pub(super) struct DialectSink<'a, 'b> {
    pub(super) walk: Walk<'a, 'b>,
}

impl rarkit::Sink for DialectSink<'_, '_> {
    type Out = Box<dyn Write + Send>;

    fn open(&mut self, member: &rarkit::MemberInfo<'_>) -> rarkit::Result<Disposition<Self::Out>> {
        let disposition = self.walk.on_open(member);
        // Stopped at the question about a file already there: the walk
        // ends here, as the reference's does, every earlier member closed.
        if self.walk.run.stopped.is_some() {
            return Err(rarkit::Error::caller(StoppedAtQuestion));
        }
        Ok(disposition)
    }

    fn close(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        Ok(self.walk.on_close(member, out, outcome)?)
    }

    fn fragment_mismatch(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
        volume: u32,
    ) -> rarkit::Result<()> {
        self.walk.on_fragment_mismatch(member, volume);
        Ok(())
    }
}

/// The dialect's concurrent `Sink`.
///
/// [`rarkit::ParallelSink`] takes `&self` because the engine's contract
/// allows several workers inside the sink at once, so the walk's whole
/// state goes behind one lock. It is not contended in practice - this
/// engine calls both methods from the walking thread - and it is not
/// there for speed: it is what lets the dialect satisfy `Sync` without
/// splitting a single run's bookkeeping across several locks that could
/// then be taken in either order.
///
/// ONE lock and not two, so that a member's `open` and its `close` are
/// each atomic against the other. Everything that decides what a member
/// prints - the volume banners, the `Creating` set, the open lines, the
/// failure list - is one run's state and is read and written together.
#[cfg(feature = "parallel")]
pub(super) struct ConcurrentSink<'a, 'b> {
    pub(super) walk: std::sync::Mutex<Walk<'a, 'b>>,
}

#[cfg(feature = "parallel")]
impl rarkit::ParallelSink for ConcurrentSink<'_, '_> {
    type Out = Box<dyn Write + Send>;

    fn open(&self, member: &rarkit::MemberInfo<'_>) -> rarkit::Result<Disposition<Self::Out>> {
        let mut walk = self
            .walk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(walk.on_open(member))
    }

    fn close(
        &self,
        member: &rarkit::MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        let mut walk = self
            .walk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(walk.on_close(member, out, outcome)?)
    }

    fn fragment_mismatch(
        &self,
        member: &rarkit::MemberInfo<'_>,
        volume: u32,
    ) -> rarkit::Result<()> {
        let mut walk = self
            .walk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        walk.on_fragment_mismatch(member, volume);
        Ok(())
    }
}
