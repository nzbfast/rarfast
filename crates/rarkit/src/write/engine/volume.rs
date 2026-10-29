//! The volume now open: its room, what a header and a fragment may take
//! of it, and the turn to the next one.

use super::*;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// The payload room left in the volume now open, in the FILE budget.
    ///
    /// The PAYLOAD budget decrements `budget` as bytes go out and this
    /// does nothing to it. The FILE budget cannot be kept that way,
    /// because what it caps is the volume's whole length: the signature,
    /// the main header, every member header, the end block and any inline
    /// recovery record all come out of the same figure. So it is counted
    /// the other way round, from where the output actually stands, which
    /// also makes it right after a correction that changed a header's
    /// length and after any block written outside this loop.
    pub(super) fn refresh_budget(&mut self) {
        let Some(cap) = self.options.volume_file_size else {
            return;
        };
        self.budget = cap
            .saturating_sub(self.out.position())
            .saturating_sub(self.tail_reserve());
    }

    /// Whether the volume now open is still inside its cap, which it must
    /// be after any block that cannot be split has gone into it.
    pub(super) fn check_volume_fits(&self) -> Result<()> {
        let Some(cap) = self.options.volume_file_size else {
            return Ok(());
        };
        if self.out.position() + self.tail_reserve() > cap {
            return Err(refuse(
                "a volume file size too small for the archive's own head, comment and end block",
            ));
        }
        Ok(())
    }

    /// Makes sure the volume now open can hold member `index`'s HEADER,
    /// opening a fresh one if it cannot and refusing if a fresh one
    /// cannot hold it either.
    ///
    /// The fragment walk in [`Run::write_member`] fits each fragment's
    /// header into the cap itself, but it only runs for a member that has
    /// bytes: a DIRECTORY entry and a zero-length member write a header
    /// and no payload, so without this their headers went into the volume
    /// with nothing measuring them and a cap of 81 bytes produced a
    /// volume of 104. Found by the `write_members` fuzz target of spec G
    /// 6.4.
    pub(super) fn fit_member_header(&mut self, index: usize, wants_payload: bool) -> Result<()> {
        if self.options.volume_file_size.is_none() {
            return Ok(());
        }
        let least = u64::from(wants_payload);
        for attempt in 0..2 {
            self.refresh_budget();
            let mut scratch = std::mem::take(&mut self.header_scratch);
            let digest = self.stored(self.placeholder_digest(index));
            self.member_header(index, Fragment::Whole, 0, digest, &mut scratch);
            let need = self.on_disk(scratch.bytes.len()) + least;
            self.header_scratch = scratch;
            if need <= self.budget {
                return Ok(());
            }
            // A volume that has already taken something can be closed and
            // the member started in a fresh one; a FRESH volume that
            // cannot hold this header is a cap no run can honour.
            if attempt == 1 || self.out.position() <= self.head_bytes {
                return Err(refuse(
                    "a volume file size too small for a member's own header",
                ));
            }
            self.next_volume()?;
        }
        Ok(())
    }

    /// What a volume must keep free for the blocks that CLOSE it: the end
    /// header, and an inline recovery record when one is on.
    ///
    /// The quick-open block is not in this figure because it cannot occur
    /// here: it belongs to the reference layout, which `Writer::new`
    /// refuses on a volume set (spec G 3.6 question 2).
    ///
    /// **The recovery record is reserved at the size the FULL cap would
    /// need.** Its length follows the protected region's, which is the
    /// volume's own bytes up to the record (SPEC-L 3.5.1), so the exact
    /// figure is not known until the payload has been placed and the
    /// payload cannot be placed until the figure is known. The record's
    /// length never falls as the protected region grows, so reserving at
    /// `P = cap` is always enough; it over-reserves by the difference the
    /// record's shard length makes over that range, which is tens of
    /// bytes on a volume of a megabyte, and it never exceeds the cap,
    /// which is the promise the budget makes.
    pub(super) fn tail_reserve(&self) -> u64 {
        let Some(cap) = self.options.volume_file_size else {
            return 0;
        };
        let end = self.on_disk(match self.options.format {
            WriteFormat::Rar5 => rar5::end_header(true).len(),
            WriteFormat::Rar4(_) => rar4::end_block(&rar4::EndPlan {
                volume_set: true,
                next_volume: true,
                volume_number: self.volume as u16,
            })
            .len(),
        });
        let recovery = match (self.options.recovery_percent, self.options.format) {
            (Some(percent), WriteFormat::Rar5) => {
                match crate::recovery::rr5::Rr5Plan::new(cap, percent) {
                    Ok(plan) => {
                        let data = plan.data_len();
                        data + self.on_disk(
                            rar5::service_header(
                                SERVICE_RECOVERY,
                                data,
                                Some(0),
                                self.service_host(),
                                true,
                                Some(u64::from(percent)),
                                self.options.reserve,
                            )
                            .len(),
                        )
                    }
                    // A cap this plan cannot be made for is one the run
                    // will refuse when it comes to write the record; the
                    // reserve says nothing about it here.
                    Err(_) => 0,
                }
            }
            // The RAR 4 family refuses a recovery record on a split set
            // (spec G 3.11), so there is nothing to keep room for.
            _ => 0,
        };
        end + recovery
    }

    /// The payload room for one fragment once its OWN header is paid for
    /// out of the same cap (the FILE budget only).
    ///
    /// The header declares the packed length, so its own length follows
    /// the room being chosen. `header_len` never falls as `room` rises, so
    /// reducing `room` by the overshoot only ever moves downwards and the
    /// loop settles; four passes is far more than the vint widths can
    /// need, and the result is checked rather than assumed.
    pub(super) fn fit_header(
        &mut self,
        index: usize,
        written: u64,
        stream: u64,
        first: bool,
        mut room: u64,
    ) -> u64 {
        let available = self.budget;
        let encrypting = self.crypt.is_some();
        // The digest a measured header carries is a PLACEHOLDER of the
        // right kind, which is what the header laid down carries too when
        // the real one is not known yet, so the two are the same length
        // (spec G 3.7.2).
        let laid = self.stored(self.placeholder_digest(index));
        let mut scratch = std::mem::take(&mut self.header_scratch);
        for _ in 0..4 {
            if room == 0 {
                break;
            }
            let last = written + room == stream;
            let fragment = match (first, last) {
                (true, true) => Fragment::Whole,
                (true, false) => Fragment::First,
                (false, true) => Fragment::Last,
                (false, false) => Fragment::Middle,
            };
            let packed = if encrypting && last {
                padded_len(room)
            } else {
                room
            };
            self.member_header(index, fragment, packed, laid, &mut scratch);
            let need = self.on_disk(scratch.bytes.len()) + packed;
            if need <= available {
                break;
            }
            room = room.saturating_sub(need - available);
        }
        self.header_scratch = scratch;
        room
    }

    // ---- progress (spec G 3.13, SPEC-API 7.1) ---------------------------

    /// The volume now open is finished: hand it back and report it.
    ///
    /// A volume is reported when it is CLOSED AND COMPLETE, which is
    /// after its end block and after the provider has taken it back.
    pub(super) fn close_volume(&mut self) -> Result<()> {
        // BEFORE `finish_volume`, which hands the volume's kept copy
        // away: this is the instant that copy is at its longest, and it
        // is the largest single term a recovery run holds.
        self.note_peak();
        let index = self.volume;
        self.out.finish_volume()?;
        self.progress.volume_done(index)
    }

    /// The largest a single fragment's data area can be, which is the
    /// volume's own cap: a fragment is cut when the volume fills and a
    /// volume is never longer than its cap (spec G 3.10.1).
    ///
    /// `Writer::new` refuses the two budgets together, so at most one of
    /// them is set and whichever it is bounds a fragment.
    pub(super) fn fragment_ceiling(&self) -> Option<u64> {
        self.options.volume_file_size.or(self.options.volume_size)
    }

    /// The packed size field's width for the next fragment of the member
    /// being streamed in cases (b) and (c) (since 28 Sep
    /// 2026): the width of the least of the volume's remaining room and
    /// a BOUND on the packed bytes the member has still to place.
    ///
    /// The held walk writes each fragment's true length at its minimum
    /// width. A fragment that fills its volume holds the room, and so does
    /// this, so the two headers agree; only a LAST fragment, whose length
    /// this walk cannot know when it lays the header down, can take one
    /// more digit than the held walk gives it. The bound is
    /// [`crate::encode::drive::packed_most`] of the WHOLE member, with a
    /// margin (a sixty-fourth and 64 KiB), so that a stream which runs
    /// over the engine's own per-block estimate is still covered, less the
    /// member's packed bytes in the fragments already closed; a correction
    /// that would not fit is refused where it is made, never written.
    ///
    /// **A function of the member's declared size, the volume's room and
    /// the bytes already placed, and of nothing the walk has pulled**
    /// (decided 1 Oct 2026). Until then the bound was the
    /// input NOT YET PULLED plus the packed bytes pending, and the header
    /// is laid after the walk's first pull: so the width followed how much
    /// that pull took, which is a flush of the one engine (its depth the
    /// memory policy's, `Run::staged_depth`) or a whole round of the
    /// segment team (as many stretches as engines). A 512 MiB member whose
    /// bound sat just above 2^28 took a five byte field from one engine
    /// and a four byte one from a team of 24, on the same input: the
    /// archive followed the machine's cores
    /// (measured 1 Oct 2026). Now every walk of
    /// one member writes the width the header would have had if it were
    /// laid before anything was pulled.
    pub(super) fn fragment_reserve(&self, index: usize) -> usize {
        let size = self.members[index].size;
        let whole =
            crate::encode::drive::packed_most(usize::try_from(size).unwrap_or(usize::MAX)) as u64;
        let bound = whole
            .saturating_add(whole / 64)
            .saturating_add(64 << 10)
            .saturating_sub(self.stream.placed);
        // An encrypted last fragment carries its padded length, up to a
        // cipher block past the room it was given.
        let pad = if self.crypt.is_some() {
            CIPHER_BLOCK as u64
        } else {
            0
        };
        rar5::vint_width_of(bound.min(self.budget).saturating_add(pad).max(1))
    }

    /// Opens the next volume: the open one is sealed with its end header,
    /// and the new one opens with its own signature and main header.
    pub(super) fn next_volume(&mut self) -> Result<()> {
        self.write_quick_open()?;
        self.write_recovery()?;
        self.write_end(true)?;
        self.close_volume()?;
        self.cached.clear();
        self.volume += 1;
        if self.options.is_rar4() && self.volume >= R4_MAX_VOLUMES {
            return Err(refuse(
                "more volumes than a RAR 4 end block can number, which is 65,535",
            ));
        }
        self.out.start_volume()?;
        self.write_archive_head(false)?;
        self.budget = self.options.volume_size.unwrap_or(u64::MAX);
        self.refresh_budget();
        // A solid run does not cross a volume boundary: the history it
        // would continue is in a file the reader may not hold, so the
        // encoder's history goes with the run.
        self.solid_run = false;
        // **A member whose encode is IN FLIGHT keeps its history across
        // the boundary.** What ends at a volume boundary is the SOLID
        // run BETWEEN members (spec G 3.9); this member's own compressed
        // stream is cut here and not ended, and a reader joins its
        // fragments into one stream over one window. The history goes
        // when the member does instead (`StreamState::crossed`), which
        // is where the member-at-a-time walk drops it, so the two walks
        // hand the member after it the same encoder state.
        if self.stream.in_flight {
            self.stream.crossed = true;
        } else if let Some(encoder) = &mut self.encoder {
            encoder.reset_history();
        }
        // The batch staged under the run that just ended goes with it.
        // Its members that this volume did not reach were encoded
        // carrying a history the next volume does not have, so their
        // packed bytes are dropped here and produced again from the reset
        // run. No byte of the output turns on this: a batch is a wave's
        // WIDTH and never a member's bytes (`Run::may_batch`).
        self.keep_unwritten();
        self.ahead_len = 0;
        Ok(())
    }

    // ---- headers --------------------------------------------------------

    /// The width member `index`'s PACKED size field is reserved at, or
    /// none for the minimum width the value needs.
    ///
    /// **Spec G 3.5's one exception to rule 2**, decided on 19 Sep 2026 and
    /// folded into that section, EXTENDED on 20 Sep
    /// 2026 and NARROWED the same day: in the DEFAULT
    /// layout, the packed size field is written at a reserved width for a
    /// member that is either (a) part of a SOLID run in a VOLUME SET, or
    /// (b) a member of a NON-SOLID volume set LARGER THAN ONE WINDOW
    /// THAT THIS WRITE IS STREAMING UNDER THE CALLER'S MEMORY CEILING.
    /// Nothing else: not a member of a non-solid volume set that is one
    /// window or smaller, not a case (b) member the write is holding
    /// whole, not any member of a single-volume archive, not a directory,
    /// not the unpacked size field, and not the reference layout, each of
    /// which is a condition below.
    ///
    /// **What case (b) buys, and what it costs.** A streamed member's
    /// packed bytes go to the volume as the encoder produces them
    /// (`Run::write_member_streamed`) instead of being held whole until
    /// its size is known, which was the last term of a write's working
    /// memory to follow the ARCHIVE rather than the options.
    /// It costs one or two bytes in this field and, because the streamed
    /// walk is a chain of windows rather than one region, some wall. So
    /// the rule spends neither unless the caller asked: with no ceiling
    /// named, case (b) is held whole and writes the minimum width, which
    /// is what `Run::over_ceiling` decides and what makes the two
    /// modes' archives differ in this one field. The size threshold is
    /// the one the streamed walk already applies to a solid member,
    /// unchanged for both cases.
    ///
    /// **The width is the vint width of the member's UNPACKED size**,
    /// which is what a writer knows before it encodes, and that is 3.5's
    /// own rule rather than 3.6.4's table. The emitter widens the field
    /// to the value when the value needs more, which is 3.5's open point
    /// and the one thing this had to answer: see
    /// `tests/solid_volume_reserved_width.rs`, which measures what a RAR
    /// 5 encoder can actually do to incompressible bytes and what
    /// reference `unrar` 7.23 accepts in this position.
    ///
    /// **What answers this is a WIDTH and not a patch.** 3.5 describes
    /// the header being laid down with the reservation, the member
    /// encoded, and the field patched, and only one of the two walks
    /// does that: `Run::write_member_streamed` lays the reserved field
    /// down and corrects it where it lies. The other walk has the packed
    /// bytes already when it builds the header - a batch produces every
    /// packed size in it before any of their headers is laid down, and a
    /// member the streamed walk did not take is encoded whole before its
    /// own - so it writes the true value at this width in one go and
    /// patches nothing. Either way what reaches the archive is a packed
    /// size vint of this width, padded, which is the shape 3.5
    /// specifies, so the two walks write the same archive.
    pub(super) fn packed_reserve(&self, index: usize) -> Option<usize> {
        // Cases (b) and (c) while their walk is laying a fragment down: the
        // width chosen for that fragment (`Run::fragment_reserve`).
        if self.stream.in_flight && self.stream.reserve.is_some() {
            return self.stream.reserve;
        }
        let width = self.reserve_width(index)?;
        // Case (a) is every member of a solid volume set, whatever the
        // policy. Case (b) is a member of a non-solid one, and it
        // reserves only where the write is actually STREAMING it: held
        // whole, it writes the minimum-width vint rule 2 asks for and its
        // bytes are the ones the code wrote before 20 Sep 2026. Asking
        // `Run::streams_packed` rather than the budget alone is what
        // keeps the byte from being spent on a member that would pay it
        // and stream anyway - an encrypted one, or one whose reservation
        // would not cover the volume's cap - and it is 3.5's own wording
        // for case (b), "THAT THE WRITER STREAMS UNDER A BUDGET".
        (self.options.solid || self.streams_packed(index)).then_some(width)
    }

    /// The width a reservation would take for member `index`, with no
    /// question asked about which case it is in or whether it streams:
    /// `None` where no member of this run reserves at all.
    ///
    /// It exists so that [`Run::streams_packed`], which has to know
    /// whether the reservation covers a whole volume, and
    /// [`Run::packed_reserve`], which has to know whether the member
    /// streams, are not each other's callers.
    pub(super) fn reserve_width(&self, index: usize) -> Option<usize> {
        if self.options.reference_layout() || !self.options.volume_set() {
            return None;
        }
        let member = &self.members[index];
        if self.member_stored(index) || member.is_directory || member.size == 0 {
            return None;
        }
        Some(rar5::vint_width_of(member.size))
    }
}
