//! The inline recovery record (spec G 3.11): its bounds, its locator and
//! the two ways it is laid.

use super::*;

/// The protected length above which a recovery record is computed from
/// the volume read back instead of from a copy of it
/// (`Run::recovery_reads_back`): [`MemoryPolicy::DEFAULT_LIMIT`]. This
/// crate's own tests move it, so that the read back is exercised on
/// volumes small enough to test; nothing in a shipped build can.
pub(super) fn recovery_copy_limit() -> u64 {
    #[cfg(test)]
    if let Some(limit) = RECOVERY_COPY_LIMIT.with(std::cell::Cell::get) {
        return limit;
    }
    MemoryPolicy::DEFAULT_LIMIT
}

#[cfg(test)]
thread_local! {
    pub(super) static RECOVERY_COPY_LIMIT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Sets the limit [`recovery_copy_limit`] answers on this thread, or puts
/// it back with `None`.
#[cfg(test)]
pub(crate) fn set_recovery_copy_limit(limit: Option<u64>) {
    RECOVERY_COPY_LIMIT.with(|cell| cell.set(limit));
}

/// The piece an inline recovery record computed in place is laid down and
/// read back in (`Run::write_recovery_in_place`): large enough that the
/// calls cost nothing beside the bytes, small enough to be no figure in
/// the run's working memory.
pub(super) const RECOVERY_LAY_CHUNK: u64 = 1 << 20;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// Whether this run's recovery records are computed from each volume
    /// READ BACK rather than from a copy of it (decided 28 Sep
    /// 2026).
    ///
    /// Both give the same bytes. The copy is the whole volume in memory and
    /// the read back is a few megabytes, but on aarch64 the read back's
    /// record costs more wall than the copy's (an Apple M3 Mac, timed: 0.66x to
    /// 0.78x of the copy's wall on 4 and 12 GiB volumes, where x86-64 read
    /// 1.12x to 3.99x faster). So the copy is kept wherever it is small, and
    /// the read back is taken only where the copy would pass
    /// [`MemoryPolicy::DEFAULT_LIMIT`], the working limit SPEC-API 8.4
    /// gives a caller who names none, which is also where a copy starts to
    /// cost a machine its memory: 512 MiB. The bound is on the VOLUME, from
    /// the caller's own figures (the volume cap, or the members' declared
    /// sizes), never from the machine, so the same options give the same
    /// choice everywhere. An output that cannot be read back keeps the
    /// copy whatever its size, as it always did.
    ///
    /// **Above 100 percent the record is counted too** (spec L 3.5.1 takes
    /// percentages to 1,000). The copy's route holds the volume, the
    /// encode's rows and the data area, and the data area a second time
    /// in the copy once it is written: `1 + 3 * percent / 100` times the
    /// volume, 4 times at 100 percent and 31 times at 1,000. Up to 100
    /// the rule above stands as it was timed. Past it, a volume is copied
    /// only while all of that fits the same limit, about 16 MiB of volume
    /// at 1,000 percent, and is otherwise read back, where the record
    /// costs `rr5::in_place_bytes` whatever the volume's length: at most
    /// 158 MiB at 1,000 percent.
    pub(super) fn recovery_reads_back(&self) -> bool {
        if !self.out.can_read_back() {
            return false;
        }
        let bound = self.protected_bound();
        let limit = recovery_copy_limit();
        bound > limit || self.copy_route_bytes(bound) > limit
    }

    /// What the copy's route holds for a volume of `protected` bytes when
    /// the percentage is above 100, and zero at or under it, where the
    /// volume's own length decides (`Run::recovery_reads_back`).
    fn copy_route_bytes(&self, protected: u64) -> u64 {
        let (Some(percent), WriteFormat::Rar5) =
            (self.options.recovery_percent, self.options.format)
        else {
            return 0;
        };
        if percent <= 100 {
            return 0;
        }
        crate::recovery::rr5::Rr5Plan::new(protected, percent).map_or(0, |plan| {
            protected
                .saturating_add(crate::recovery::rr5::whole_slice_bytes(&plan))
                .saturating_add(plan.data_len())
        })
    }

    /// An upper bound on one volume's protected bytes, from the caller's
    /// figures: the volume cap for a set capped by its file, the payload
    /// budget and an eighth over for one capped by its payload, and for
    /// any run the whole archive's bound (`Run::archive_bound`), which a
    /// set's volume cannot pass either.
    pub(super) fn protected_bound(&self) -> u64 {
        let archive = self.archive_bound();
        let volume = match (self.options.volume_file_size, self.options.volume_size) {
            (Some(cap), _) => cap,
            (None, Some(size)) => size.saturating_add(size / 8).saturating_add(1 << 20),
            (None, None) => u64::MAX,
        };
        archive.min(volume)
    }

    /// An upper bound on the whole archive's bytes before any recovery
    /// record: every member's payload, its name and an allowance for its
    /// header, and an eighth over for a compressor that does not shrink
    /// what it is given. Saturating, so a caller's declared sizes cannot
    /// wrap it.
    pub(super) fn archive_bound(&self) -> u64 {
        let mut body: u64 = RAR5_SIGNATURE.len() as u64 + (64 << 10);
        for member in &self.members {
            body = body
                .saturating_add(member.size)
                .saturating_add(member.size / 8)
                .saturating_add(member.name.len() as u64)
                .saturating_add(512);
        }
        body
    }

    /// An UPPER BOUND on one volume's bytes, for the copy spec G 3.11
    /// keeps so the recovery record covers the volume as it finally
    /// stands (`Out::keep_a_copy`, which says why the bound is wanted).
    ///
    /// A volume set has its bound stated: the cap is the promise the
    /// budget makes and no volume passes it. A single archive has none,
    /// so one is built here - every member's payload, its name and an
    /// allowance for its header, an eighth over for a compressor that
    /// does not shrink what it is given, and the record itself. Short is
    /// the only failure mode that costs anything, and the terms are
    /// saturating so a caller's declared sizes cannot wrap it.
    ///
    /// `None` when no bound fits a `usize`: the copy is then grown as it
    /// always was, which is correct and merely not flat.
    pub(super) fn tee_reserve(&self) -> usize {
        if let Some(cap) = self.options.volume_file_size {
            return usize::try_from(cap).unwrap_or(usize::MAX / 2);
        }
        let body = self.archive_bound();
        let record = match (self.options.recovery_percent, self.options.format) {
            (Some(percent), WriteFormat::Rar5) => {
                crate::recovery::rr5::Rr5Plan::new(body, percent).map_or(0, |plan| plan.data_len())
            }
            // The RAR 4 record is the tags, two bytes to each 512 byte
            // sector, and at most `percent` per cent of the protected
            // length in parity sectors, with one sector as its floor
            // (spec L 3.7). An allowance and not a length: nothing here
            // has to be the figure the record will come out at.
            (Some(percent), WriteFormat::Rar4(_)) => body
                .div_ceil(100)
                .saturating_mul(u64::from(percent))
                .saturating_add(body / 256)
                .saturating_add(4096),
            _ => 0,
        };
        // Half of `usize` rather than all of it: a reserve this large is
        // already hopeless and an allocator asked for `usize::MAX` aborts
        // the process rather than answering.
        usize::try_from(body.saturating_add(record)).unwrap_or(usize::MAX / 2)
    }

    /// The inline recovery record (spec G 3.11): a service block after the
    /// last member and after the quick-open block, and before the end
    /// header, over the bytes of the volume as they stand at that point.
    ///
    /// Everything before it must be FINAL when it is built, which is why
    /// the sink keeps a copy of the volume while this is on: a header
    /// whose checksum was patched in afterwards has to be covered as it
    /// finally stands, not as it was first laid down. The copy is one
    /// volume, and it is the only thing in this package whose size
    /// follows the archive rather than the format.
    pub(super) fn write_recovery(&mut self) -> Result<()> {
        let Some(percent) = self.options.recovery_percent else {
            return Ok(());
        };
        self.write_default_locator()?;
        // The reference layout wrote this block's offset into the locator
        // before a member was written; this is where it had to land.
        debug_assert!(self.reference.as_ref().is_none_or(|plan| {
            plan.recovery_offset == Some(self.out.position() - RAR5_SIGNATURE.len() as u64)
        }));
        if !self.out.keeping_a_copy() {
            return self.write_recovery_in_place(percent);
        }
        match self.options.format {
            WriteFormat::Rar5 => {
                // The recovery fold's width is `MemoryPolicy::max_workers`
                // against the pool, the row API 8.2 assigns it, and the
                // pool is the write's own, so the fold's threads are
                // helpers within `workers` too (`width`).
                // What the encode holds beside the copy is counted while
                // it runs (spec G 3.7.3 rule 2).
                let protected = self.out.kept().len() as u64;
                let plan = crate::recovery::rr5::Rr5Plan::new(protected, percent)?;
                self.recovery_scratch = crate::recovery::rr5::whole_slice_bytes(&plan);
                self.note_peak();
                let kept = self.out.kept();
                let workers = self.options.memory.max_workers;
                let record = width::on_pool(|| {
                    crate::recovery::rr5::encode_with_workers(kept, percent, workers)
                });
                self.recovery_scratch = 0;
                let record = record?;
                let header = rar5::service_header(
                    SERVICE_RECOVERY,
                    record.len() as u64,
                    self.recovery_data_crc()
                        .then(|| crate::checksum::crc32(&record)),
                    self.service_host(),
                    true,
                    Some(u64::from(percent)),
                    self.options.reserve,
                );
                self.write_header(&header)?;
                // The data area is held here and, once written, in the
                // copy as well.
                self.recovery_scratch = record.len() as u64;
                let written = self.out.write(&record);
                self.note_peak();
                self.recovery_scratch = 0;
                written?;
            }
            WriteFormat::Rar4(_) => {
                let (record, counts) = crate::recovery::legacy::build(self.out.kept(), percent)?;
                let header = rar4::recovery_sub_block(&record, self.rar4_service_host(), &counts);
                self.write_header(&header)?;
                self.out.write(&record)?;
            }
        }
        Ok(())
    }

    /// Whether the RAR 5 `RR` service header carries its data area's
    /// CRC32: KEPT in the default layout, OMITTED in the reference layout
    /// as rar 7.23 omits it (spec G 3.11, SPEC-L question 5);
    /// a reader accepts both, since the records carry their own CRC-64.
    pub(super) fn recovery_data_crc(&self) -> bool {
        !self.options.reference_layout()
    }

    /// The width the DEFAULT layout reserves for the recovery record's
    /// offset in each volume's main header, or `None` when it writes no
    /// locator (spec G 3.5 rule 1 and 3.11).
    ///
    /// The width is the reference's: 3.6.3's estimate over EVERY member of
    /// the archive, the same in every volume (measured on rar 7.23 `-v`
    /// sets, 30 Sep 2026: a first volume holding only small members still
    /// takes the whole archive's width). Only a RAR 5 record; only where
    /// the output can patch, since a hold would keep the whole volume a
    /// second time beside the recovery copy, and an output that cannot
    /// patch keeps the bytes it wrote before (by design,
    /// as case (c) of the streamed walk splits bytes by output kind);
    /// and not under header encryption, where "the first byte after the
    /// signature" (spec F 3.2.8) and "the start of the main header" are
    /// two different places and which one rar 7.23 counts from is not
    /// measured yet.
    pub(super) fn default_locator_width(&self) -> Option<usize> {
        if self.options.reference_layout()
            || self.options.recovery_percent.is_none()
            || !matches!(self.options.format, WriteFormat::Rar5)
            || self.options.encrypt_headers
            || !self.out.can_patch()
        {
            return None;
        }
        Some(self.locator_reserve())
    }

    /// Spec G 3.6.3's reserved width, over every member of the archive.
    pub(super) fn locator_reserve(&self) -> usize {
        rar5::locator_reserve_width(
            self.members
                .iter()
                .map(|m| (if m.is_directory { 0 } else { m.size }, m.name)),
        )
    }

    /// Writes the recovery record's offset into the open volume's locator,
    /// which the main header reserved at `default_locator`'s width. It
    /// runs before the record is computed, so the record covers the main
    /// header as it finally stands. An offset the width cannot hold is
    /// left at 0, which spec F 3.2.8 reads as "no such record": a reader
    /// then finds the record by the header chain. The estimate is over the
    /// members alone, at a payload times 4,096, so it takes a comment far
    /// larger than the members to get there: a 3 MiB comment beside one
    /// member of 20 bytes does. That is a valid archive and not a fault,
    /// so it is not asserted against.
    pub(super) fn write_default_locator(&mut self) -> Result<()> {
        let Some(width) = self.default_locator else {
            return Ok(());
        };
        let offset = self.out.position() - RAR5_SIGNATURE.len() as u64;
        if rar5::vint_width_of(offset) > width {
            return Ok(());
        }
        let header = rar5::main_header(&self.main_plan(Some(rar5::Locator {
            quick_open: None,
            recovery: Some((offset, width)),
        })));
        let at = self.main_at;
        self.correct_header(at, &header)
    }

    /// The inline recovery record over an output that can be read back:
    /// the same block [`Run::write_recovery`] writes from its copy, byte
    /// for byte, computed from the volume where it lies instead.
    ///
    /// RAR 5: the service header goes down with a placeholder data CRC32,
    /// the data area as zeros, and `rr5::encode_in_place` fills the area in
    /// from the volume read back a group at a time; the header is then
    /// corrected in place with the area's CRC32, under the same
    /// initialisation vector when headers are enciphered, so the block is
    /// exactly as long. The record's protected length is fixed before any
    /// of it is written, and nothing before it moves afterwards. Working
    /// memory is `rr5::in_place_bytes`, a few megabytes whatever the
    /// volume's length.
    ///
    /// RAR 4: the volume is read back in order into the XOR record's
    /// encoder, which holds the data area (the tags and the parity sectors,
    /// `percent` of the protected length and two bytes a sector) and never
    /// the volume. The data area has to be whole before its sub block can
    /// be written, since the block's header carries its checksum.
    pub(super) fn write_recovery_in_place(&mut self, percent: u32) -> Result<()> {
        let protected = self.out.position();
        match self.options.format {
            WriteFormat::Rar5 => {
                let plan = crate::recovery::rr5::Rr5Plan::new(protected, percent)?;
                let data = plan.data_len();
                let host = self.service_host();
                let reserve = self.options.reserve;
                let keep_crc = self.recovery_data_crc();
                let service = |crc: u32| {
                    rar5::service_header(
                        SERVICE_RECOVERY,
                        data,
                        keep_crc.then_some(crc),
                        host,
                        true,
                        Some(u64::from(percent)),
                        reserve,
                    )
                };
                let placeholder = service(0);
                let at = self.write_header(&placeholder)?;
                let area_at = self.out.position();
                let zeros = vec![0u8; data.min(RECOVERY_LAY_CHUNK) as usize];
                let mut left = data;
                while left > 0 {
                    let take = left.min(zeros.len() as u64) as usize;
                    self.out.write(&zeros[..take])?;
                    left -= take as u64;
                }
                drop(zeros);
                self.recovery_scratch = crate::recovery::rr5::in_place_bytes(&plan);
                self.note_peak();
                // The in-place fold runs its own team beside this thread,
                // which reads the next group, so the team is given at most
                // the helpers the budget allows; none means the fold runs
                // here. The census counts the team at that width.
                let team = self.options.memory.max_workers.min(self.helpers().max(1));
                #[cfg(test)]
                let _team = hold(if team > 1 { team } else { 0 });
                let crc =
                    crate::recovery::rr5::encode_in_place(&mut self.out, &plan, area_at, team);
                self.recovery_scratch = 0;
                let crc = crc?;
                if keep_crc {
                    let header = service(crc);
                    debug_assert_eq!(header.len(), placeholder.len());
                    self.correct_header(at, &header)?;
                }
            }
            WriteFormat::Rar4(_) => {
                let mut encoder = crate::recovery::legacy::LegacyEncoder::new(protected, percent);
                let mut chunk = vec![0u8; protected.min(RECOVERY_LAY_CHUNK) as usize];
                let mut at = 0;
                while at < protected {
                    let take = (protected - at).min(chunk.len() as u64) as usize;
                    self.out.read_back(at, &mut chunk[..take])?;
                    encoder.push(&chunk[..take]);
                    at += take as u64;
                }
                drop(chunk);
                let (record, counts) = encoder.finish();
                self.recovery_scratch = record.len() as u64;
                self.note_peak();
                self.recovery_scratch = 0;
                let header = rar4::recovery_sub_block(&record, self.rar4_service_host(), &counts);
                self.write_header(&header)?;
                self.out.write(&record)?;
            }
        }
        Ok(())
    }
}
