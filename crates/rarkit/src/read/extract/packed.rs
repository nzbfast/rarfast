//! A member's packed bytes as its decoder asks for them: the read a
//! decoder pulls from, the tally of what it took, the scratch a worker
//! keeps and the buffered source over either.

use super::*;

/// The tally of a decode whose bytes are not output: a RAR 4 family
/// link's target, decoded for `open` and never delivered (spec F 3.8.1).
pub(super) struct Unreported;

impl Tally for Unreported {
    fn output(&mut self, _: usize) -> Result<()> {
        Ok(())
    }
}

/// Where one member's packed bytes come from, in order, with `Ok(0)` for
/// the end of the member and nothing else.
///
/// Layer 3's [`MemberStream`] is one of these and was the only one until
/// 19 Sep 2026; the concurrent driver of [`crate::read::concurrent`] adds a
/// second that reads a member's own byte range straight from the volume it
/// sits in, which is what lets a worker decode a member the walk has
/// already passed. Everything below this trait is common to both.
pub(crate) trait PackedRead {
    fn read(&mut self, into: &mut [u8]) -> Result<usize>;
    /// A read, and the CRC32 of what it returned where the reader
    /// computed one anyway (`MemberStream::read_crc`).
    fn read_crc(&mut self, into: &mut [u8]) -> Result<(usize, Option<u32>)> {
        Ok((self.read(into)?, None))
    }
    /// Where the next packed bytes are, for the wide verify
    /// (`read::wide`). A reader that cannot say answers `Narrow` and is
    /// read the ordinary way, which is every reader but the walk's.
    #[cfg(feature = "parallel")]
    fn span(&mut self) -> Result<Span> {
        Ok(Span::Narrow)
    }
    /// Bytes of a `Span::Range` read and hashed elsewhere; see
    /// `MemberStream::passed`. Never reached for a reader whose `span` is
    /// always `Narrow`.
    #[cfg(feature = "parallel")]
    fn passed(&mut self, _crc: u32, _len: u64) -> Result<()> {
        Ok(())
    }
    /// The error a source ending at `at` inside the member is.
    #[cfg(feature = "parallel")]
    fn truncated_at(&mut self, at: u64) -> Error {
        Error::new(ErrorKind::Truncated).with_offset(at)
    }
    /// A source error met by the wide reader, as the walk reports it.
    #[cfg(feature = "parallel")]
    fn broken_by(&mut self, error: Error) -> Error {
        error
    }
    /// Whether the CRC32 handed to `passed` is judged against the
    /// fragment's packed checksum: an encrypted member's wide read then
    /// hashes its CIPHERTEXT as well, and only then.
    #[cfg(feature = "parallel")]
    fn packed_crc_wanted(&self) -> bool {
        false
    }
    /// For a reader that is a pool worker's, how its wide read is granted
    /// ([`Slice`]). `None` is the walk's own stream, which reads the whole
    /// range at the width it was given, as it always has.
    #[cfg(feature = "parallel")]
    fn grant_slice(&self) -> Option<Slice> {
        None
    }
    /// Whether [`Self::lead`] gives this reader's fragments to a team kept
    /// across them (`read::across`): the walk's own stream, and no other.
    #[cfg(feature = "parallel")]
    fn leads(&self) -> bool {
        false
    }
    /// The rest of the fragment being read, taken whole; see
    /// `MemberStream::lead`. Never reached for a reader that does not
    /// [`Self::leads`].
    #[cfg(feature = "parallel")]
    fn lead(
        &mut self,
        _floor: u64,
        _room: Option<u64>,
        _held: Option<crate::read::forwarded::Held>,
    ) -> Result<crate::read::across::Next> {
        Ok(crate::read::across::Next::Over)
    }
    /// The error a source ending at `at` of `volume`, inside a fragment
    /// taken ahead, is.
    #[cfg(feature = "parallel")]
    fn truncated_in(&mut self, volume: u32, at: u64) -> Error {
        Error::new(ErrorKind::Truncated)
            .with_volume(volume)
            .with_offset(at)
    }
    /// A source error met inside a fragment of `volume` taken ahead.
    #[cfg(feature = "parallel")]
    fn broken_in(&mut self, volume: u32, error: Error) -> Error {
        let error = self.broken_by(error);
        if error.volume().is_none() {
            error.with_volume(volume)
        } else {
            error
        }
    }
    /// A fragment taken ahead whose packed CRC32 disagreed with its field.
    #[cfg(feature = "parallel")]
    fn fragment_failed(&mut self, _volume: u32) {}
    /// Bytes of a fragment taken from `volume` joined, up to `upto` of it;
    /// see `MemberStream::passed_in`.
    #[cfg(feature = "parallel")]
    fn passed_in(&mut self, _volume: u32, _upto: u64, _len: u64) -> Result<()> {
        Ok(())
    }
    /// The last byte taken from `volume` is joined; see
    /// `MemberStream::fragment_joined`.
    #[cfg(feature = "parallel")]
    fn fragment_joined(&mut self, _volume: u32) -> Result<()> {
        Ok(())
    }
    /// The read abreast has ended; see `MemberStream::fragments_ended`.
    #[cfg(feature = "parallel")]
    fn fragments_ended(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<V: Volumes, N: Notify> PackedRead for MemberStream<'_, '_, V, N> {
    fn read(&mut self, into: &mut [u8]) -> Result<usize> {
        MemberStream::read(self, into)
    }
    fn read_crc(&mut self, into: &mut [u8]) -> Result<(usize, Option<u32>)> {
        MemberStream::read_crc(self, into)
    }
    #[cfg(feature = "parallel")]
    fn span(&mut self) -> Result<Span> {
        MemberStream::span(self)
    }
    #[cfg(feature = "parallel")]
    fn passed(&mut self, crc: u32, len: u64) -> Result<()> {
        MemberStream::passed(self, crc, len)
    }
    #[cfg(feature = "parallel")]
    fn truncated_at(&mut self, at: u64) -> Error {
        MemberStream::truncated_at(self, at)
    }
    #[cfg(feature = "parallel")]
    fn broken_by(&mut self, error: Error) -> Error {
        MemberStream::broken_by(self, error)
    }
    #[cfg(feature = "parallel")]
    fn packed_crc_wanted(&self) -> bool {
        MemberStream::packed_crc_wanted(self)
    }
    #[cfg(feature = "parallel")]
    fn leads(&self) -> bool {
        true
    }
    #[cfg(feature = "parallel")]
    fn lead(
        &mut self,
        floor: u64,
        room: Option<u64>,
        held: Option<crate::read::forwarded::Held>,
    ) -> Result<crate::read::across::Next> {
        MemberStream::lead(self, floor, room, held)
    }
    #[cfg(feature = "parallel")]
    fn truncated_in(&mut self, volume: u32, at: u64) -> Error {
        MemberStream::truncated_in(self, volume, at)
    }
    #[cfg(feature = "parallel")]
    fn fragment_failed(&mut self, volume: u32) {
        MemberStream::fragment_failed(self, volume);
    }
    #[cfg(feature = "parallel")]
    fn passed_in(&mut self, volume: u32, upto: u64, len: u64) -> Result<()> {
        MemberStream::passed_in(self, volume, upto, len)
    }
    #[cfg(feature = "parallel")]
    fn fragment_joined(&mut self, volume: u32) -> Result<()> {
        MemberStream::fragment_joined(self, volume)
    }
    #[cfg(feature = "parallel")]
    fn fragments_ended(&mut self) -> Result<()> {
        MemberStream::fragments_ended(self)
    }
}

impl<R: PackedRead + ?Sized> PackedRead for &mut R {
    fn read(&mut self, into: &mut [u8]) -> Result<usize> {
        (**self).read(into)
    }
    fn read_crc(&mut self, into: &mut [u8]) -> Result<(usize, Option<u32>)> {
        (**self).read_crc(into)
    }
    #[cfg(feature = "parallel")]
    fn span(&mut self) -> Result<Span> {
        (**self).span()
    }
    #[cfg(feature = "parallel")]
    fn passed(&mut self, crc: u32, len: u64) -> Result<()> {
        (**self).passed(crc, len)
    }
    #[cfg(feature = "parallel")]
    fn truncated_at(&mut self, at: u64) -> Error {
        (**self).truncated_at(at)
    }
    #[cfg(feature = "parallel")]
    fn broken_by(&mut self, error: Error) -> Error {
        (**self).broken_by(error)
    }
    #[cfg(feature = "parallel")]
    fn packed_crc_wanted(&self) -> bool {
        (**self).packed_crc_wanted()
    }
    #[cfg(feature = "parallel")]
    fn grant_slice(&self) -> Option<Slice> {
        (**self).grant_slice()
    }
    #[cfg(feature = "parallel")]
    fn leads(&self) -> bool {
        (**self).leads()
    }
    #[cfg(feature = "parallel")]
    fn lead(
        &mut self,
        floor: u64,
        room: Option<u64>,
        held: Option<crate::read::forwarded::Held>,
    ) -> Result<crate::read::across::Next> {
        (**self).lead(floor, room, held)
    }
    #[cfg(feature = "parallel")]
    fn truncated_in(&mut self, volume: u32, at: u64) -> Error {
        (**self).truncated_in(volume, at)
    }
    #[cfg(feature = "parallel")]
    fn fragment_failed(&mut self, volume: u32) {
        (**self).fragment_failed(volume);
    }
    #[cfg(feature = "parallel")]
    fn passed_in(&mut self, volume: u32, upto: u64, len: u64) -> Result<()> {
        (**self).passed_in(volume, upto, len)
    }
    #[cfg(feature = "parallel")]
    fn fragment_joined(&mut self, volume: u32) -> Result<()> {
        (**self).fragment_joined(volume)
    }
    #[cfg(feature = "parallel")]
    fn fragments_ended(&mut self) -> Result<()> {
        (**self).fragments_ended()
    }
}

/// The member's packed bytes as a decoder reads them: layer 3's stream,
/// decrypted where the member is encrypted (spec K).
pub(super) struct Packed<R: PackedRead> {
    pub(super) stream: R,
    pub(super) decryptor: Option<MemberDecryptor>,
    /// Plaintext a caller's buffer was too small to take. Only the small
    /// buffer path below ever fills it, and never with more than it holds.
    pub(super) spill: [u8; SPILL],
    pub(super) spill_at: usize,
    pub(super) spill_len: usize,
}

/// The staging buffer for a caller whose own is smaller than the cipher's
/// carry, which nothing on the read path does but which costs one array to
/// be right about.
pub(super) const SPILL: usize = 64;

impl<R: PackedRead> Packed<R> {
    pub(super) fn new(stream: R, decryptor: Option<MemberDecryptor>) -> Packed<R> {
        Packed {
            stream,
            decryptor,
            spill: [0; SPILL],
            spill_at: 0,
            spill_len: 0,
        }
    }

    /// Whether this member's packed bytes are enciphered.
    ///
    /// The one question `read::extract::copy` asks of the cipher, and it
    /// asks it to decide an ARRANGEMENT and never a result: the overlap
    /// of `overlap_plan` is for the member that has a serial cipher in
    /// front of a wide hasher, and there is nothing to overlap without
    /// one.
    #[cfg(feature = "parallel")]
    pub(super) fn encrypted(&self) -> bool {
        self.decryptor.is_some()
    }

    /// [`Self::read`] with the stream's CRC32 of the bytes, which is the
    /// PLAINTEXT's only where there is no cipher: a ciphertext CRC is a
    /// different domain even for a stored member, so an encrypted member
    /// shares nothing.
    pub(super) fn read_crc(&mut self, into: &mut [u8]) -> Result<(usize, Option<u32>)> {
        if self.decryptor.is_none() {
            return self.stream.read_crc(into);
        }
        Ok((self.read(into)?, None))
    }

    /// Fill `into` with the next plaintext packed bytes. `Ok(0)` is the end
    /// of the member.
    pub(super) fn read(&mut self, into: &mut [u8]) -> Result<usize> {
        if self.decryptor.is_none() {
            return self.stream.read(into);
        }
        if self.spill_at < self.spill_len {
            let take = (self.spill_len - self.spill_at).min(into.len());
            into[..take].copy_from_slice(&self.spill[self.spill_at..self.spill_at + take]);
            self.spill_at += take;
            return Ok(take);
        }
        if into.is_empty() {
            return Ok(0);
        }
        let room = self.decryptor.as_ref().expect("checked").pending();
        if into.len() > room {
            return self.decrypt_into(into);
        }
        // A buffer with no room for the straddling block's plaintext: take
        // the bytes through the staging array and hand back what fits.
        let mut staging = [0u8; SPILL];
        let plain = self.decrypt_into(&mut staging)?;
        let take = plain.min(into.len());
        into[..take].copy_from_slice(&staging[..take]);
        self.spill[..plain - take].copy_from_slice(&staging[take..plain]);
        self.spill_at = 0;
        self.spill_len = plain - take;
        Ok(take)
    }

    /// Decrypt the next packed bytes into the FRONT of `into`, which must
    /// be longer than the cipher's carry, and answer how many.
    ///
    /// The decryptor turns the buffer into plaintext in place; the head of a
    /// straddling block comes back from its own storage and is put in front
    /// of the body, in the room the decryptor asked to be left for it, so
    /// the plaintext is contiguous and no byte is ever shifted.
    pub(super) fn decrypt_into(&mut self, into: &mut [u8]) -> Result<usize> {
        loop {
            let dec = self.decryptor.as_mut().expect("checked by the caller");
            let room = dec.pending();
            debug_assert!(into.len() > room);
            let got = self.stream.read(&mut into[room..])?;
            if got == 0 {
                // A trailing partial block is the member's business, not an
                // error.
                return Ok(0);
            }
            let dec = self.decryptor.as_mut().expect("checked by the caller");
            let mut head = [0u8; 16];
            let (head_len, body) = {
                let plain = dec.update(&mut into[room..room + got]);
                head[..plain.head.len()].copy_from_slice(plain.head);
                (plain.head.len(), plain.body)
            };
            into[room - head_len..room].copy_from_slice(&head[..head_len]);
            let plain = head_len + body;
            if plain > 0 {
                if head_len < room {
                    into.copy_within(room - head_len..room + body, 0);
                }
                return Ok(plain);
            }
        }
    }
}

/// What an operation counts as one member's decoded bytes land, beyond the
/// member's own running totals.
///
/// The sequential path counts the WHOLE operation here and ticks the
/// caller's `Progress` and its cancel flag ([`Ticker`]). A worker of the
/// concurrent driver counts only its own member, because `Progress` belongs
/// to the walking thread (SPEC-API 4.4), and polls the cancel flag alone.
pub(crate) trait Tally {
    /// `n` more decoded bytes have reached this member's output.
    fn output(&mut self, n: usize) -> Result<()>;
}

/// The sequential path's tally: the operation's byte count, the caller's
/// `Progress` once per [`TICK`] of output, and the cancel flag with it
/// (spec F 3.7.6).
pub(super) struct Ticker<'a, 'p, P: Progress> {
    pub(super) bytes: &'a mut u64,
    /// What the driver delivered beside the walk ([`Run::base`]).
    pub(super) base: u64,
    pub(super) since: &'a mut u64,
    pub(super) gate: &'a Gate<'p, P>,
    pub(super) cancel: Option<&'a AtomicBool>,
}

impl<P: Progress> Tally for Ticker<'_, '_, P> {
    fn output(&mut self, n: usize) -> Result<()> {
        *self.bytes += n as u64;
        *self.since += n as u64;
        if *self.since >= TICK {
            *self.since = 0;
            self.gate.borrow_mut().output(*self.bytes + self.base)?;
            if self.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(Error::new(ErrorKind::Cancelled));
            }
        }
        Ok(())
    }
}

/// The two buffers one decode reuses across every member it runs: the
/// window a block-at-a-time decoder reads through and the copy buffer a
/// stored member is carried through. One set per operation on the
/// sequential path and one per WORKER on the concurrent one, never one per
/// member (spec F 7.3.5, 7.3.6).
#[derive(Default)]
pub(crate) struct Scratch {
    pub(super) packed: Vec<u8>,
    pub(super) copy: Vec<u8>,
    /// The overlap's SECOND chunk (`overlap_plan`), kept here for the
    /// same reason `copy` is: so a run of members does not allocate one
    /// per member. It is empty until an encrypted BLAKE2sp member is
    /// overlapped, and the two together never exceed what `copy` alone
    /// holds on the serial path, the ceiling being halved before it is
    /// taken twice.
    pub(super) copy_pair: Vec<u8>,
    /// The largest ring the seam of 3.7.7 has held for a member of this
    /// operation.
    ///
    /// A high-water mark rather than a live figure, because the ring is
    /// built and dropped inside one member's scope and the report is
    /// taken after the last member: what a caller has to be able to bound
    /// is the most that was ever held at once, which SPEC-API 8.5
    /// requires to be testable from outside exactly as 8.3's windows are.
    #[cfg(feature = "parallel")]
    pub(crate) ring_peak: u64,
    /// The seam's ring buffers, kept between members for the reason
    /// `copy` is: one set per operation, never one per member. Empty until
    /// a member is overlapped; `ring_peak` above already counts them.
    #[cfg(feature = "parallel")]
    pub(crate) ring: Vec<seam::Slab>,
    /// A redirection member's target, as `open` is handed it (spec F
    /// 3.8.1): kept for the operation, so no member allocates one.
    pub(crate) target: Vec<u8>,
}

impl Scratch {
    /// Shrink every buffer grown past [`SCRATCH_KEEP`] back to it, giving
    /// the pages above it to the kernel first (`crate::pages::release`,
    /// which acts only on 2 MiB and more, as for a ring). Under a NAMED
    /// budget, after every member ([`decode`]).
    pub(crate) fn give_back(&mut self) {
        for buf in [&mut self.packed, &mut self.copy, &mut self.copy_pair] {
            if buf.capacity() > SCRATCH_KEEP {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                if buf.len() > SCRATCH_KEEP {
                    crate::pages::release(&mut buf[SCRATCH_KEEP..]);
                }
                buf.truncate(SCRATCH_KEEP);
                buf.shrink_to(SCRATCH_KEEP);
            }
        }
    }

    /// The bytes these buffers hold NOW, the seam's high-water ring left
    /// out: what the process counters are charged with (API section 8,
    /// whole-process).
    pub(crate) fn live_bytes(&self) -> u64 {
        let buffers = self.packed.capacity() as u64
            + self.copy.capacity() as u64
            + self.copy_pair.capacity() as u64
            + self.target.capacity() as u64;
        // The seam's slabs kept idle between members; while a seam runs
        // they are out of this list and charged by the seam itself.
        #[cfg(feature = "parallel")]
        let buffers = buffers + self.ring.iter().map(seam::Slab::held_bytes).sum::<u64>();
        buffers
    }

    /// The bytes these buffers hold, which the report counts as working
    /// memory.
    pub(crate) fn held_bytes(&self) -> u64 {
        let buffers = self.packed.capacity() as u64
            + self.copy.capacity() as u64
            + self.copy_pair.capacity() as u64
            + self.target.capacity() as u64;
        #[cfg(feature = "parallel")]
        let buffers = buffers + self.ring_peak;
        buffers
    }
}

/// The decoded bytes of one member, as a decoder writes them.
pub(super) struct Decoded<'a, W: std::io::Write, T: Tally> {
    pub(super) member: &'a mut Member<W>,
    pub(super) blake: &'a mut Option<Box<Blake2sp>>,
    pub(super) tally: &'a mut T,
}

impl<W: std::io::Write, T: Tally> LzSink for Decoded<'_, W, T> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        emit(self.member, self.blake, self.tally, bytes).map(|_| ())
    }
}

impl<W: std::io::Write, T: Tally> StreamOut for Decoded<'_, W, T> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        emit(self.member, self.blake, self.tally, bytes).map(|_| ())
    }
}

/// A member's packed bytes with enough of them held at once for a decoder
/// that needs a block's payload contiguous (spec H2 3.1).
///
/// This is the one place the read-ahead bound of spec F 3.7.2 is exceeded,
/// and only as far as the format forces: a RAR 5 block's payload length
/// field is 24 bits (spec H2 4.1), so the buffer is bounded by the format
/// and never by a member's size. It grows on demand and is reused across
/// members, so nothing here allocates per member (7.3.5).
pub(super) struct Buffered<R: PackedRead> {
    pub(super) packed: Packed<R>,
    pub(super) buf: Vec<u8>,
    pub(super) at: usize,
    pub(super) filled: usize,
    pub(super) ended: bool,
    /// The concurrent reads a fill of 2 MiB and up is cut into
    /// (`cursor::deep`); 1 reads it as one.
    #[cfg(feature = "parallel")]
    pub(super) parts: usize,
    /// The engine limit of a NAMED budget, which the buffer's growth is
    /// held under; `None` where no budget was named.
    cap: Option<u64>,
    /// The buffer's bytes past `base`, charged to the meter as it grows
    /// (SPEC-API 8.4.1, the account's item 7).
    grown: crate::memory::Held,
    /// What the buffer held when it was taken from the operation's
    /// scratch, which the scratch's own charge already counts.
    base: usize,
}

impl<R: PackedRead> Buffered<R> {
    /// `buf`, the operation's kept buffer, over `packed`, its growth
    /// charged and held under `policy`'s limit where one was named.
    pub(super) fn over(
        packed: Packed<R>,
        buf: Vec<u8>,
        policy: &crate::MemoryPolicy,
        parts: usize,
    ) -> Buffered<R> {
        #[cfg(not(feature = "parallel"))]
        let _ = parts;
        Buffered {
            packed,
            at: 0,
            filled: 0,
            ended: false,
            #[cfg(feature = "parallel")]
            parts,
            cap: policy.limit_named.then_some(policy.working_limit),
            grown: crate::memory::Held::default(),
            base: buf.capacity(),
            buf,
        }
    }

    /// Grow the buffer to hold `want` bytes, `wish` where the budget has
    /// room for the geometric step.
    ///
    /// The packed block buffer is not a term of the up-front account: no
    /// header read before the decode says how large a member's blocks
    /// are, and priced at the format's bound it refuses members a width
    /// of one holds with room to spare. So it is charged here, as it
    /// grows, and a block whose buffer would pass what a NAMED budget
    /// leaves is refused HERE, before a byte of its payload is read:
    /// `LimitExceeded { resource: BlockBuffer }`, `needed` what the
    /// operation would hold with it.
    ///
    /// Before that refusal the thread asks ONCE for what its operation
    /// holds that comes back without it ([`crate::memory::make_room`]), and
    /// prices again: on a solid archive's walk, the bytes queued for the
    /// caller's thread, which stood in this price and refused a member the
    /// sequential path reads under the same limit (27 Oct 2026). The walk
    /// waits for them; the limit is never passed.
    fn grow(&mut self, want: usize, wish: usize) -> Result<()> {
        let mut room = wish.max(want);
        if let Some(cap) = self.cap {
            let mut asked = false;
            loop {
                let beside = crate::memory::op_current().saturating_sub(self.charged());
                let with = |len: usize| beside.saturating_add(len.saturating_sub(self.base) as u64);
                room = wish.max(want);
                if with(room) > cap {
                    room = want;
                }
                if with(room) <= cap {
                    break;
                }
                if !std::mem::replace(&mut asked, true) && crate::memory::make_room() {
                    continue;
                }
                return Err(Error::new(ErrorKind::LimitExceeded {
                    resource: crate::error::Resource::BlockBuffer,
                    needed: with(room),
                    limit: cap,
                }));
            }
        }
        self.buf.resize(room, 0);
        self.recharge();
        Ok(())
    }

    /// The bytes of the buffer the meter is charged with from here.
    fn charged(&self) -> u64 {
        self.buf.capacity().saturating_sub(self.base) as u64
    }

    fn recharge(&mut self) {
        let charged = self.charged();
        self.grown.set(charged);
    }
}

impl<R: PackedRead> PackedSource for Buffered<R> {
    fn fill(&mut self, want: usize) -> Result<()> {
        let want = want.min(MAX_PACKED);
        if self.filled - self.at >= want || self.ended {
            return Ok(());
        }
        if self.at > 0 {
            self.buf.copy_within(self.at..self.filled, 0);
            self.filled -= self.at;
            self.at = 0;
        }
        if self.buf.len() < want {
            // Geometric, so a member of N blocks costs O(log N)
            // allocations whatever the block sizes are.
            let wish = self.buf.len().saturating_mul(2).min(MAX_PACKED);
            self.grow(want, wish)?;
        }
        while self.filled < want {
            // Always hand the reader more room than the cipher's carry, so
            // no read is ever served through the staging path.
            if self.buf.len() - self.filled < SPILL {
                let room = self.buf.len() + SPILL;
                self.grow(room, room)?;
            }
            let room = &mut self.buf[self.filled..];
            #[cfg(feature = "parallel")]
            let got = match self.parts {
                1 => self.packed.read(room)?,
                parts => crate::read::cursor::deep::deeply(parts, || self.packed.read(room))?,
            };
            #[cfg(not(feature = "parallel"))]
            let got = self.packed.read(room)?;
            if got == 0 {
                self.ended = true;
                break;
            }
            self.filled += got;
        }
        Ok(())
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.at..self.filled]
    }

    fn advance(&mut self, n: usize) {
        self.at = (self.at + n).min(self.filled);
    }

    /// A read has come back empty: nothing lies past what is held.
    fn exhausted(&self) -> bool {
        self.ended
    }
}
