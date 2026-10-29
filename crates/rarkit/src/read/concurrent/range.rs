//! A worker's read of its member's packed range, and its tally.

use super::*;

/// One member's packed bytes, read straight out of the volume they sit in.
///
/// The sequential path's [`MemberStream`](crate::read::walk::MemberStream)
/// crosses volumes and joins fragments; this one never has to, because a
/// member that spans volumes is dispatched only with the fragments the
/// walk sends as it crosses to them (`extract::Split`), and this reads
/// them in that order. What the two share
/// is the meaning of the answers: `Ok(0)` is the end of the member and
/// nothing else, and a source that stops before the range's end is
/// `Truncated` naming the member.
pub(super) struct RangeRead<'a> {
    pub(super) src: Arc<dyn RangeSource>,
    pub(super) at: u64,
    pub(super) end: u64,
    pub(super) name: &'a [u8],
    /// A split member's further fragments, as the walk sends them.
    pub(super) more: Option<std::sync::mpsc::Receiver<extract::Next>>,
    /// The packed CRC32 of the fragment being read, and the value its
    /// header carries, where it is judged (spec F 3.5.6).
    pub(super) judge: Option<(crate::checksum::Crc32, u32)>,
    /// The volumes of the leading fragments whose packed CRC32 disagreed
    /// with their field (spec F 3.5.6): a diagnostic for the close.
    pub(super) mismatches: Vec<u32>,
    /// A split member's LAST fragment header, once the walk has sent it.
    pub(super) last: Option<Box<FileHdr>>,
    /// The walk stopped before sending the member's last fragment.
    pub(super) yielded: bool,
    /// For a split member, the volume of the fragment being read: its read
    /// errors name it, as the walk's own read of the member would.
    pub(super) volume: Option<u32>,
    /// The read buffer, and how much of it is unread.
    ///
    /// MEASURED, not reasoned. Without it the concurrent driver was
    /// SLOWER than the sequential one at width 1 - 190 ms against 119 ms
    /// on `f/extract-par-8x16-m3` - because the sequential path has TWO
    /// layers of buffering under a decoder and this had one. `Buffered`
    /// above the packed source asks for exactly the bytes the next block
    /// header needs, which for RAR 5 is a handful, and on the walking
    /// thread those handfuls are served out of `Cursor`'s own 4 KiB
    /// window; a worker reading its range straight from the source issued
    /// one `read_at` per handful instead. The buffer is this driver's
    /// `Cursor`: one per WORKER, reused across every member it decodes,
    /// never one per member.
    pub(super) buf: Vec<u8>,
    pub(super) at_in_buf: usize,
    pub(super) filled: usize,
    /// Set when the READ itself failed, as layer 3 sets it: a source that
    /// ended under a member, or one that refused. Those end the OPERATION,
    /// where a decoder's verdict on one member's bytes ends only that
    /// member (spec F section 8). The sequential path reads that
    /// distinction off `MemberStream::broken`, and a worker that did not
    /// keep it would turn a truncated archive into a member-sized failure
    /// and carry on - which is the same class of defect, the other way up.
    pub(super) broken: bool,
    /// Nonzero where [`PackedRead::span`] answers ranges, so that
    /// `extract::copy` reads this member wide, and then the fewest lanes
    /// it is read wide at ([`job_wide`]): a STORED member, under AES-CBC
    /// or clear ([`job_wide_clear`]). A member under an older cipher reads
    /// in order, and a compressed one never asks.
    pub(super) wide: usize,
    /// Whether the wide read is taken only while another member is being
    /// decoded ([`Written::Beside`], for a member that is written).
    pub(super) beside_others: bool,
    /// When the member's ranges are handed to its writer to be cut
    /// ([`stored_cut_when`]), and whether the joined wide read may take
    /// it otherwise (`extract::Slice`).
    pub(super) cut: extract::CutWhen,
    pub(super) uncut: bool,
    /// The fragment being read's place among those the walk has forwarded
    /// ahead (`read::forwarded`): dropped when it is read to its end. `None`
    /// for a member's first fragment, which the job itself brought.
    pub(super) held: Option<crate::read::forwarded::Held>,
}

impl PackedRead for RangeRead<'_> {
    fn read(&mut self, into: &mut [u8]) -> Result<usize> {
        let outcome = self.read_inner(into);
        self.told(outcome)
    }

    /// Where the member's next packed bytes are, for the wide read of an
    /// encrypted stored member ([`RangeRead::wide`]); `Narrow` for every
    /// other member, as before 1 Oct 2026.
    ///
    /// The worker's own window is given back first: its unread bytes are a
    /// copy of the source just behind `at`, none of them delivered or
    /// judged yet, so the range starts at the first byte the member has
    /// not been handed. A fragment read to its end is judged and the next
    /// one the walk sends is opened here, exactly as [`Self::read`] does.
    fn span(&mut self) -> Result<Span> {
        if self.wide == 0 {
            return Ok(Span::Narrow);
        }
        #[cfg(feature = "test-support")]
        crate::probe::note_job_span();
        self.at -= (self.filled - self.at_in_buf) as u64;
        self.at_in_buf = 0;
        self.filled = 0;
        loop {
            if self.at < self.end {
                return Ok(Span::Range {
                    source: Arc::clone(&self.src),
                    at: self.at,
                    len: self.end - self.at,
                });
            }
            if self.more.is_none() {
                return Ok(Span::End);
            }
            let next = self.next_fragment();
            if !self.told(next)? {
                return Ok(Span::End);
            }
        }
    }

    /// `len` bytes at the reader's position were read and hashed by the
    /// wide read, and `crc` is the CRC32 of their PACKED bytes: the
    /// fragment's own check takes it as a serial read's would have (spec F
    /// 3.5.6).
    fn passed(&mut self, crc: u32, len: u64) -> Result<()> {
        debug_assert!(len <= self.end - self.at);
        if let Some((judge, _)) = &mut self.judge {
            judge.append(crc, len);
        }
        self.at += len;
        Ok(())
    }

    fn truncated_at(&mut self, at: u64) -> Error {
        self.broken = true;
        let error = Error::new(ErrorKind::Truncated)
            .with_member(self.name)
            .with_offset(at);
        match self.volume {
            Some(volume) => error.with_volume(volume),
            None => error,
        }
    }

    fn broken_by(&mut self, error: Error) -> Error {
        self.broken = true;
        match self.volume {
            Some(volume) if error.volume().is_none() => error.with_volume(volume),
            _ => error,
        }
    }

    fn packed_crc_wanted(&self) -> bool {
        self.judge.is_some()
    }

    fn grant_slice(&self) -> Option<extract::Slice> {
        Some(extract::Slice {
            bytes: GRANT_SLICE,
            fewest: self.wide,
            beside_others: self.beside_others,
            cut: self.cut,
            uncut: self.uncut,
        })
    }
}

impl RangeRead<'_> {
    /// A read's or a crossing's answer as the member reports it: a failure
    /// ends the OPERATION ([`RangeRead::broken`]) and names the fragment's
    /// volume where the member is split.
    pub(super) fn told<T>(&mut self, outcome: Result<T>) -> Result<T> {
        if outcome.is_err() {
            self.broken = true;
        }
        outcome.map_err(|e| match self.volume {
            Some(volume) if e.volume().is_none() => e.with_volume(volume),
            _ => e,
        })
    }

    pub(super) fn read_inner(&mut self, into: &mut [u8]) -> Result<usize> {
        loop {
            let got = self.read_fragment(into)?;
            if got > 0 {
                if let Some((crc, _)) = &mut self.judge {
                    crc.update(&into[..got]);
                }
                return Ok(got);
            }
            if self.more.is_none() || !self.next_fragment()? {
                return Ok(0);
            }
        }
    }

    /// Read a SPLIT member on to its end once its decode has succeeded, as
    /// the walk's `extract::land` drains its own stream: every leading
    /// fragment is judged and the walk's `End`, the LAST fragment's
    /// header, is received. A decoder stops at the member's declared size
    /// and may leave packed bytes behind it, and a verdict read off the
    /// FIRST header then compares against a leading fragment's packed
    /// CRC32 (spec F 3.5.6). A stored copy reads to the end anyway, so
    /// this reads nothing there; an unsplit member has nothing to receive.
    pub(super) fn drain_split(&mut self) -> Result<()> {
        if self.more.is_none() {
            return Ok(());
        }
        let mut sink = [0u8; 8 * 1024];
        while self.read(&mut sink)? != 0 {}
        Ok(())
    }

    /// The fragment being read is done: judge it, and move on to the next
    /// one the walk sends. `false` is the end of the member.
    pub(super) fn next_fragment(&mut self) -> Result<bool> {
        if let Some((crc, stored)) = self.judge.take() {
            if crc.finish() != stored {
                // A split member's fragment always knows its volume.
                self.mismatches.push(self.volume.unwrap_or(0));
            }
        }
        // The fragment just read is no longer one the walk is ahead by.
        self.held = None;
        let next = self.more.as_ref().map(|more| more.recv());
        match next {
            Some(Ok(extract::Next::Fragment {
                src,
                data,
                checksum,
                volume,
                held,
            })) => {
                self.held = Some(held);
                self.src = src;
                self.volume = Some(volume);
                self.at = data.start;
                self.end = data.end;
                self.at_in_buf = 0;
                self.filled = 0;
                self.judge = checksum.map(|c| (crate::checksum::Crc32::new(), c));
                Ok(true)
            }
            Some(Ok(extract::Next::End(last))) => {
                self.last = Some(last);
                self.more = None;
                Ok(false)
            }
            // The walk stopped before the member's last fragment: its own
            // error is the operation's, and this member ends as broken.
            Some(Err(_)) | None => {
                self.more = None;
                self.yielded = true;
                Err(Error::new(ErrorKind::Truncated).with_member(self.name))
            }
        }
    }

    pub(super) fn read_fragment(&mut self, into: &mut [u8]) -> Result<usize> {
        if self.at_in_buf == self.filled {
            if let Some(got) = self.straight_through(into)? {
                return Ok(got);
            }
            self.fill()?;
            if self.at_in_buf == self.filled {
                return Ok(0);
            }
        }
        let take = (self.filled - self.at_in_buf).min(into.len());
        into[..take].copy_from_slice(&self.buf[self.at_in_buf..self.at_in_buf + take]);
        self.at_in_buf += take;
        Ok(take)
    }

    /// A request BIGGER than the window, read into the caller's own buffer
    /// with no staging copy at all. `None` when the request is one the
    /// window should serve, which leaves the caller on [`fill`] as before.
    ///
    /// **This is where a breadth-one stored member was losing its wall,
    /// and the window is why.** [`READ_BUF`] exists for a DECODER, which
    /// asks for the bytes a block header needs and would otherwise issue
    /// one `read_at` per handful; the comment on the field says so. A
    /// stored member is the opposite caller. It asks for its whole copy
    /// buffer at once (`extract::STORED_REQUEST`), and the window then
    /// answers that request 64 KiB at a time out of a staging buffer, so
    /// every byte of the member is copied TWICE - once by the kernel into
    /// [`RangeRead::buf`], once by `copy_from_slice` into the caller's -
    /// and the member is walked in 64 KiB steps whatever it asked for.
    /// A caller asking for more than the window holds wants neither.
    ///
    /// **It is the CONCURRENT path's defect and not the walk's**, which is
    /// why it reads as a breadth-one cost when the same member is timed
    /// through the tool: the sequential path's `Cursor::take` already
    /// reads straight into the caller's buffer, so a member the walking
    /// thread carries never paid this, and one the driver dispatches
    /// always did. A single-member archive is dispatched like any other.
    ///
    /// **MEASURED.** `rarfast` against the same tree with this bypass out,
    /// on one 256 MiB stored member, four 64 MiB ones and nine 16 MiB
    /// ones, `rar a -m0`, RAR 5 with a CRC32 record; nine runs a cell
    /// after a discarded warmup. A laptop, 18 cores, one-minute load 17
    /// to 27, so INDICATIVE and not a gate figure. Wall and CPU in ms:
    ///
    /// | leg | cmd | wall | CPU | peak RSS |
    /// |---|---|---|---|---|
    /// | one 256 MiB | `t` | 21.9 to **17.7** | 24.0 to **20.0** | 4 to 4 MiB |
    /// | one 256 MiB | `x` | 48.5 to **40.7** | 50.3 to **42.2** | 4 to 4 MiB |
    /// | 4 x 64 MiB | `t` | 9.2 to **6.8** | 29.6 to **20.8** | 4 to 4 MiB |
    /// | 4 x 64 MiB | `x` | 24.2 to **22.1** | 80.5 to **60.3** | 4 to 4 MiB |
    /// | 9 x 16 MiB | `t` | 4.5 to **3.7** | 24.3 to **17.3** | 5 to 5 MiB |
    /// | 9 x 16 MiB | `x` | 10.8 to 10.8 | 60.1 to **44.5** | 5 to 5 MiB |
    ///
    /// Wall falls or holds on every leg and CPU falls on every one of
    /// them, by up to thirty percent, at no cost in peak RSS. That is the
    /// shape a removed copy has and not the shape a spent thread has.
    /// **It is not a breadth-one effect**: every DISPATCHED member paid
    /// the second copy, so the multi-member legs move too. It reads as a
    /// breadth-one cost at the tool only because a breadth-one archive has
    /// nothing else in it.
    ///
    /// **Three WIDER variants were built and all three lost**, and they
    /// are recorded so the next reader does not spend the same day: the
    /// same range read by several threads at once, the member checksum
    /// folded across lanes with `Crc32::combine`, and the two together.
    /// Every one of them cost wall AND multiplied CPU by four to nine,
    /// because this stage is bound by memory bandwidth and by the kernel's
    /// own serialisation on one file, not by a core. They are measured figures.
    /// Nothing here is a thread.
    ///
    /// The bytes and the order are the window's exactly: this is taken
    /// only when the window is EMPTY, so the two paths never interleave
    /// and a caller alternating large and small requests sees one stream.
    /// A source free to answer SHORT is what
    /// `a_dispatched_stored_member_crosses_the_workers_window_intact`
    /// holds it to, one of its dribble widths being a single byte.
    pub(super) fn straight_through(&mut self, into: &mut [u8]) -> Result<Option<usize>> {
        let left = self.end - self.at;
        let want = left.min(into.len() as u64) as usize;
        if want <= READ_BUF {
            return Ok(None);
        }
        // The walk's own helper, so a source that answers short or is
        // INTERRUPTED is treated here exactly as it is on the sequential
        // path: read until the request is full or the source ends, and
        // never report a partial answer as the end of the member.
        let got = crate::read::cursor::read_upto_at(self.src.as_ref(), self.at, &mut into[..want])?;
        if got == 0 {
            return Err(Error::new(ErrorKind::Truncated)
                .with_member(self.name)
                .with_offset(self.at));
        }
        self.at += got as u64;
        Ok(Some(got))
    }

    /// Refill the buffer from the member's remaining range. `Ok(())` with
    /// nothing filled is the end of the member.
    pub(super) fn fill(&mut self) -> Result<()> {
        // Clamped in `u64` and THEN narrowed, exactly as layer 3 is: a
        // member above 4 GiB whose remainder narrows to zero would other-
        // wise report the end of its data in the middle of itself.
        let left = self.end - self.at;
        if left == 0 {
            return Ok(());
        }
        if self.buf.len() < READ_BUF {
            self.buf.resize(READ_BUF, 0);
        }
        let want = left.min(self.buf.len() as u64) as usize;
        let got = match self.src.read_at(self.at, &mut self.buf[..want]) {
            Ok(got) => got,
            Err(e) => return Err(Error::new(ErrorKind::Source(e)).with_offset(self.at)),
        };
        if got == 0 {
            return Err(Error::new(ErrorKind::Truncated)
                .with_member(self.name)
                .with_offset(self.at));
        }
        self.at += got as u64;
        self.at_in_buf = 0;
        self.filled = got;
        Ok(())
    }
}

/// A worker's tally: the member's own bytes are counted by the member, so
/// all this owes is the cancel flag, polled once per [`TICK`] of output
/// exactly as the walking thread polls it (spec F 3.7.6).
///
/// `Progress` is NOT reported from here. It belongs to the thread that
/// called `extract`, and `extract_parallel` takes none at all.
pub(super) struct Polled<'a> {
    pub(super) cancel: Option<&'a AtomicBool>,
    pub(super) since: u64,
}

impl Tally for Polled<'_> {
    fn output(&mut self, n: usize) -> Result<()> {
        self.since += n as u64;
        if self.since >= TICK {
            self.since = 0;
            if self.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(Error::new(ErrorKind::Cancelled));
            }
        }
        Ok(())
    }
}
