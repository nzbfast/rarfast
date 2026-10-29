//! Layer 1, the framing: one forward walk over one volume's blocks
//! (spec F 2.1).
//!
//! The reader never holds more than one block's header bytes, reads through
//! one buffer of at least 4 KiB, and never issues one read per field. Names
//! go into one arena that grows geometrically, so nothing allocates per
//! member or per name.

use crate::crypto::{HeaderReader, KeyCache, Rar5Cipher};
use crate::error::{Corruption, Error, ErrorKind, Resource, Result};
use crate::memory::MemoryPolicy;
use crate::read::block::{Block, Fields, FileHdr};
use crate::read::cursor::Cursor;
use crate::read::detect::signature_len;
use crate::read::{rar13, rar4, rar5, vint, Format, ReadOptions};
use crate::source::RangeSource;
use crate::types::Password;

/// The read options and the caches shared between the volumes of one set
/// (API section 4.2): derived keys, one per (salt, password) pair rather
/// than one per volume.
pub(crate) struct ReadCtx {
    /// The caller's options.
    pub options: ReadOptions,
    /// Derived keys, shared across the volumes of one set.
    pub keys: KeyCache,
    /// One header decrypt buffer, reused across headers and zeroed on drop.
    pub headers: HeaderReader,
    /// What a NAMED budget leaves the read (8.4.1, the pre-scan,
    /// `extract::budget_floor`): the room for windows the pools admit each
    /// member against by its own need, and the workers it pays for.
    /// `None` when no budget was named or the pre-scan could not read
    /// volume 0, and the pools run as before.
    pub room: Option<crate::read::extract::Room>,
}

impl ReadCtx {
    /// A context for these options.
    pub(crate) fn new(options: ReadOptions) -> ReadCtx {
        let cancel = options.cancel.clone();
        ReadCtx {
            options,
            keys: KeyCache::new(cancel),
            headers: HeaderReader::new(),
            room: None,
        }
    }

    /// The password, or [`ErrorKind::PasswordRequired`].
    fn password(&self) -> Result<&Password> {
        self.options
            .password
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::PasswordRequired))
    }
}

/// How the blocks after the main header are encrypted.
enum HeaderCrypt {
    /// RAR 1.5 to 4.x: a fresh AES-128 chain per block from the salt that
    /// precedes it (spec K 3.6.3).
    Rar4,
    /// RAR 5: AES-256 from the archive encryption header's keys and
    /// their schedule, with each header carrying its own IV (spec K 3.7.5).
    Rar5(Box<Rar5Cipher>),
}

fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Header))
}

/// A forward walk over one volume's blocks.
pub(crate) struct BlockReader<'s, 'c> {
    cursor: Cursor<'s>,
    ctx: &'c mut ReadCtx,
    generation: Format,
    /// The signature's offset in the source.
    start: u64,
    /// The first byte after the signature, where the first block begins.
    sig_end: u64,
    /// Where the next block begins.
    pos: u64,
    /// The current header's bytes, decrypted when the headers are.
    head: Vec<u8>,
    /// One name arena for every name this walk decodes.
    arena: Vec<u8>,
    policy: MemoryPolicy,
    /// A permissive walk keeps going past a header whose checksum failed
    /// and never decrypts: it is the block dump of spec F 5.2, not a
    /// reader. `Archive::open` is never permissive (spec F 4.6).
    permissive: bool,
    done: bool,
    started: bool,
    crypt: Option<HeaderCrypt>,
    /// The size field of the header being read, for a diagnostic walk.
    declared: u64,
    /// True once a data area was declared that the source does not hold.
    overran: bool,
    /// [`ReadOptions::read_damaged`]: read through the damage the
    /// reference reads through.
    lenient: bool,
    /// Where the main header's locator says the quick open record is.
    quick_open_at: Option<u64>,
    /// Where that main header begins, which a wrong locator is reported at.
    main_at: u64,
    /// The quick open record, read only when a header fails its checksum.
    quick_open: QuickOpen,
    /// The last member header read says the member continues in the next
    /// volume, so nothing behind its data is needed of this volume.
    split_open: bool,
    /// The walk ended on damage behind such a member's data.
    cut_after_split: bool,
    /// A block this walk read begins exactly where the locator says the
    /// quick open record is (spec F 3.2.8 rule 2 case a).
    quick_open_met: bool,
    /// The block last read came from a quick open copy.
    copied: bool,
    /// How many headers of this volume were read although their own
    /// checksum failed. Counted where such a header is accepted, which no
    /// sound header reaches.
    unsound_read: u64,
}

/// The quick open record of the volume being read, for the one use
/// [`ReadOptions::read_damaged`] makes of it.
enum QuickOpen {
    /// No header has failed its checksum, so nothing was read.
    Unread,
    /// There is none, or it is not sound, or it is larger than the
    /// policy lets a member table be.
    Absent,
    /// The record's data area. `cursor` is the first entry not yet passed:
    /// a writer lays the entries down in archive order and the walk only
    /// moves forward, so every lookup resumes where the last one stopped
    /// and all of them together read the record once.
    Held {
        data: Vec<u8>,
        header_at: u64,
        cursor: usize,
    },
}

impl<'s, 'c> BlockReader<'s, 'c> {
    /// A walk of the volume whose signature sits at `start`.
    pub(crate) fn new(
        src: &'s dyn RangeSource,
        ctx: &'c mut ReadCtx,
        generation: Format,
        start: u64,
    ) -> BlockReader<'s, 'c> {
        BlockReader::over(Cursor::new(src), ctx, generation, start)
    }

    /// A walk that keeps its source alive itself, for the volume walk of
    /// spec F 2.3: one member's packed stream continues across a volume
    /// boundary, so the walk outlives the local the provider handed over.
    pub(crate) fn shared(
        src: std::sync::Arc<dyn RangeSource>,
        ctx: &'c mut ReadCtx,
        generation: Format,
        start: u64,
    ) -> BlockReader<'static, 'c> {
        BlockReader::over(Cursor::shared(src), ctx, generation, start)
    }

    fn over(
        cursor: Cursor<'s>,
        ctx: &'c mut ReadCtx,
        generation: Format,
        start: u64,
    ) -> BlockReader<'s, 'c> {
        let policy = ctx.options.memory;
        let lenient = ctx.options.read_damaged;
        let cursor = cursor.with_read_ahead(policy.read_ahead);
        let sig_end = start + signature_len(generation);
        BlockReader {
            cursor,
            ctx,
            generation,
            start,
            sig_end,
            // RAR 5 has no marker block: its first block is the byte after
            // the signature. The RAR 4 marker block IS the signature, and a
            // RAR 1.3 archive header begins with it.
            pos: if matches!(generation, Format::Rar5) {
                sig_end
            } else {
                start
            },
            head: Vec::new(),
            arena: Vec::new(),
            policy,
            permissive: false,
            done: false,
            started: false,
            crypt: None,
            declared: 0,
            overran: false,
            lenient,
            quick_open_at: None,
            main_at: 0,
            quick_open: QuickOpen::Unread,
            split_open: false,
            cut_after_split: false,
            quick_open_met: false,
            copied: false,
            unsound_read: 0,
        }
    }

    /// Give the read context back, which is what lets the volume walk drop
    /// one volume's reader and build the next volume's.
    pub(crate) fn into_ctx(self) -> &'c mut ReadCtx {
        self.ctx
    }

    /// Keep walking past a header whose checksum failed, and never decrypt:
    /// the block dump of spec F 5.2.
    // Selected by `read/dump.rs` alone, which is `#[cfg(test)]`: the block
    // dump of spec F 5.2. `Archive::open` stops on a bad header (4.6).
    #[allow(dead_code)]
    pub(crate) fn permissive(mut self) -> Self {
        self.permissive = true;
        self
    }

    /// The name arena this walk has filled.
    pub(crate) fn arena(&self) -> &[u8] {
        &self.arena
    }

    /// Take the name arena, leaving the reader with an empty one.
    pub(crate) fn take_arena(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.arena)
    }

    /// Where the arena currently ends, for a caller that resets it per
    /// member rather than keeping every name.
    pub(crate) fn arena_mark(&self) -> usize {
        self.arena.len()
    }

    /// Drop every name added since `mark`.
    pub(crate) fn arena_reset(&mut self, mark: usize) {
        self.arena.truncate(mark);
    }

    /// The current header's bytes, for the block dump.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub(crate) fn header_bytes(&self) -> &[u8] {
        &self.head
    }

    /// The size field of the header the walk stopped on.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub(crate) fn declared_size(&self) -> u64 {
        self.declared
    }

    /// Where the next block begins.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub(crate) fn position(&self) -> u64 {
        self.pos
    }

    /// The source behind the walk.
    pub(crate) fn source(&self) -> &dyn RangeSource {
        self.cursor.source()
    }

    /// This walk's own working memory: the read buffer, the one header
    /// buffer and the name arena. Nothing else in the walk allocates.
    pub(crate) fn working_bytes(&self) -> u64 {
        let record = match &self.quick_open {
            QuickOpen::Held { data, .. } => data.capacity() as u64,
            _ => 0,
        };
        self.cursor.working_bytes()
            + self.head.capacity() as u64
            + self.arena.capacity() as u64
            + record
    }

    /// Whether the walk ended on damage behind the data of a member that
    /// continues in the next volume ([`ReadOptions::read_damaged`]): the
    /// volume's end record was not read, and another volume follows.
    pub(crate) fn cut_after_split(&self) -> bool {
        self.cut_after_split
    }

    /// Whether the block last read with a failed checksum was read from
    /// the quick open record's copy of it (spec F 3.2.9.1).
    pub(crate) fn read_from_copy(&self) -> bool {
        self.copied
    }

    /// How many headers of this volume were read although their own
    /// checksum failed ([`ReadOptions::read_damaged`]), every kind of
    /// block counted. Not capped, as `Archive::damaged_headers` is: it is
    /// a count and holds nothing.
    pub(crate) fn unsound_read(&self) -> u64 {
        self.unsound_read
    }

    /// Take member data at `at` through the SAME buffer the headers are
    /// read through, so a byte the header read already fetched is not read
    /// again (spec F 7.3.3).
    pub(crate) fn take_data(&mut self, at: u64, buf: &mut [u8]) -> Result<usize> {
        self.cursor.take(at, buf)
    }

    /// See [`Cursor::holds`].
    #[cfg(feature = "parallel")]
    pub(crate) fn holds(&self, at: u64) -> bool {
        self.cursor.holds(at)
    }

    /// See [`Cursor::held_from`].
    #[cfg(feature = "parallel")]
    pub(crate) fn held_from(&self, at: u64) -> usize {
        self.cursor.held_from(at)
    }

    /// See [`Cursor::shared_source`].
    #[cfg(feature = "parallel")]
    pub(crate) fn shared_source(&self) -> Option<std::sync::Arc<dyn RangeSource>> {
        self.cursor.shared_source()
    }

    /// Whether the blocks after the main header are deciphered as they
    /// are read.
    pub(crate) fn headers_keyed(&self) -> bool {
        self.crypt.is_some()
    }

    /// The read context, for a caller that needs the key cache.
    pub(crate) fn ctx(&mut self) -> &mut ReadCtx {
        self.ctx
    }

    /// The next block, or `None` at a clean end.
    ///
    /// A convenience over [`Self::next_into`] for the callers that are
    /// not on the per-member path: it allocates nothing, but it does
    /// move the 352 byte block into an `Option` to hand it back. The
    /// extraction walk uses `next_into` instead.
    pub(crate) fn next(&mut self) -> Result<Option<Block>> {
        let mut block = Block::empty();
        if self.next_into(&mut block)? {
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Fill `into` with the next block; `false` at a clean end.
    ///
    /// The block is written straight into the caller's slot and is never
    /// moved afterwards. See [`Block::empty`] for what that is worth.
    pub(crate) fn next_into(&mut self, into: &mut Block) -> Result<bool> {
        if self.done {
            return Ok(false);
        }
        let got = match self.generation {
            Format::Rar5 => self.next_rar5(into),
            Format::Rar13 => self.next_rar13(into),
            _ => self.next_rar4(into),
        };
        let got = match got {
            Ok(got) => got,
            Err(e) if self.behind_a_split_member(&e) => {
                self.done = true;
                self.cut_after_split = true;
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        if !got {
            return Ok(false);
        }
        let next = into.end();
        // Every step of every walk advances by at least one byte: a header
        // size and data size of zero would otherwise leave the walk where
        // it was, which turns a malformed archive into a hang (spec F 4.1).
        if next <= self.pos {
            return Err(corrupt().with_offset(self.pos));
        }
        self.pos = next;
        Ok(true)
    }

    /// Whether `error` is damage this walk does not need to read past
    /// ([`ReadOptions::read_damaged`]): the last member header of the
    /// volume says its member continues in the next one, and every byte
    /// of that member's data here is held, so what is damaged is the
    /// volume's trailing records alone. Measured against unrar 7.23 on 8
    /// Oct 2026: a middle volume one byte short in its end record tests
    /// `All OK`.
    #[cold]
    fn behind_a_split_member(&self, error: &Error) -> bool {
        self.lenient
            && self.split_open
            && !self.overran
            && !self.permissive
            && matches!(
                error.kind(),
                ErrorKind::Truncated | ErrorKind::HeaderChecksum | ErrorKind::Corrupt(_)
            )
    }

    /// What spec F 3.2.8 rule 2 says of this RAR 5 volume's quick open
    /// offset, asked ONCE, when the walk of the volume has run to its end
    /// ([`ReadOptions::read_damaged`]). The offset is the one a sound main
    /// header's locator names, and it is judged against the blocks this
    /// walk read, so it never costs a member:
    ///
    /// - a block began exactly there (case a): nothing. A sound `QO`
    ///   header was the hint come true, a sound header of another kind is
    ///   ignored as the reference ignores it, and one whose checksum
    ///   failed has been reported already (4.6);
    /// - the offset is at or past the end of the volume's bytes (case b):
    ///   the volume has LOST ITS TAIL, `Truncated`;
    /// - the offset is inside the volume's bytes and no block began there
    ///   (case c): the LOCATOR is wrong, `Corrupt` at the main header.
    ///
    /// A walk that did not reach the volume's end judges nothing, and one
    /// that stopped at damage behind a member that continues has not seen
    /// what stands at an offset inside the volume, so it answers case b
    /// alone.
    pub(crate) fn locator_verdict(&self) -> Option<Error> {
        if !self.lenient || self.permissive || !self.done || self.quick_open_met {
            return None;
        }
        let at = self.quick_open_at?;
        match self.ends_before(at.saturating_add(1)) {
            Ok(true) => Some(Error::new(ErrorKind::Truncated).with_offset(self.pos)),
            Ok(false) if self.cut_after_split => None,
            Ok(false) => Some(corrupt().with_offset(self.main_at)),
            Err(e) => Some(e),
        }
    }

    /// Case b of the same rule, asked where the volume ends at a block
    /// boundary with no end record: it ends at or before the offset its
    /// locator names.
    fn quick_open_cut_off(&self) -> bool {
        self.lenient && self.quick_open_at.is_some_and(|at| at >= self.pos)
    }

    /// A RAR 5 header that did not parse or whose checksum failed.
    ///
    /// Without [`ReadOptions::read_damaged`], and for every enciphered
    /// header, it is used for nothing (spec F 4.6). With it, a sound copy
    /// in the quick open record is read in its place; failing that, a
    /// header that parses is read as it stands. Either way the block is
    /// reported unsound (spec F 4.6 rule 1, 3.2.9.1 rule 4).
    /// Answers the common fields, whether the header is sound (never,
    /// here), and for a copy where its header ends: the copy's own length
    /// decides, the damaged header's size field being one of the things
    /// damaged.
    #[cold]
    #[inline(never)]
    fn damaged_rar5(
        &mut self,
        parsed: Result<rar5::Common>,
        pos: u64,
    ) -> Result<(rar5::Common, bool, Option<u64>)> {
        if !self.lenient || self.crypt.is_some() {
            parsed.map_err(|e| e.with_offset(pos))?;
            return Err(Error::new(ErrorKind::HeaderChecksum).with_offset(pos));
        }
        self.copied = false;
        if self.quick_open_copy(pos) {
            // The copy's fields stand in for the header's; the header's
            // failure is reported all the same (3.2.9.1 rule 4).
            self.copied = true;
            let common = rar5::parse_common(&self.head).map_err(|e| e.with_offset(pos))?;
            self.unsound_read += 1;
            return Ok((common, false, Some(pos + self.head.len() as u64)));
        }
        let common = parsed.map_err(|e| e.with_offset(pos))?;
        // An encryption header changes how every later block is read: one
        // that is not sound is not believed.
        if common.btype == rar5::TYPE_ENCRYPTION {
            return Err(Error::new(ErrorKind::HeaderChecksum).with_offset(pos));
        }
        self.unsound_read += 1;
        Ok((common, false, None))
    }

    /// Replace the header in hand with the quick open record's copy of
    /// the header at `pos`, when the record holds a sound one: the entry's
    /// checksum matches, the copy parses and its own checksum matches
    /// (spec F 3.2.9.1). `false`, with the header untouched, otherwise.
    fn quick_open_copy(&mut self, pos: u64) -> bool {
        if matches!(self.quick_open, QuickOpen::Unread) {
            self.quick_open = self.load_quick_open().unwrap_or(QuickOpen::Absent);
        }
        let BlockReader {
            quick_open, head, ..
        } = self;
        let QuickOpen::Held {
            data,
            header_at,
            cursor,
        } = quick_open
        else {
            return false;
        };
        while let Some((entry, copy, next)) = rar5::quick_open_entry(data, *cursor) {
            let Some(copied_from) = header_at.checked_sub(entry.distance_back) else {
                return false;
            };
            // An entry for a later header: kept for the lookup that
            // reaches it.
            if copied_from > pos {
                return false;
            }
            *cursor = next;
            if copied_from < pos {
                continue;
            }
            let copy = &data[copy];
            let sound = entry.checksum_ok
                && rar5::parse_common(copy).is_ok_and(|common| {
                    rar5::header_checksum(copy) == common.crc && common.btype == rar5::TYPE_FILE
                });
            if sound {
                head.clear();
                head.extend_from_slice(copy);
            }
            return sound;
        }
        false
    }

    /// Read the quick open record the locator names, whole. `None` for a
    /// record that is not there, is not sound in its own header, is not a
    /// stored clear `QO` service block, or is larger than the policy's
    /// member table: nothing is allocated before those are known, and the
    /// source is asked for no byte it does not hold.
    fn load_quick_open(&mut self) -> Option<QuickOpen> {
        let at = self.quick_open_at?;
        let src = self.cursor.source();
        let mut prefix = [0u8; 4 + vint::MAX_VINT_BYTES];
        let got = crate::read::cursor::read_upto_at(src, at, &mut prefix).ok()?;
        let mut fields = 4usize;
        let size = vint::read(prefix.get(..got)?, &mut fields)?;
        let head_len = (fields as u64)
            .checked_add(size)
            .filter(|&len| len <= self.policy.max_header)?;
        let data_at = at.checked_add(head_len)?;
        if self.ends_before(data_at).ok()? {
            return None;
        }
        let mut head = vec![0u8; usize::try_from(head_len).ok()?];
        if crate::read::cursor::read_upto_at(src, at, &mut head).ok()? != head.len() {
            return None;
        }
        let common = rar5::parse_common(&head).ok()?;
        if rar5::header_checksum(&head) != common.crc || common.btype != rar5::TYPE_SERVICE {
            return None;
        }
        let mut file = FileHdr::empty();
        rar5::parse_file_into(&head, &common, data_at, &mut file).ok()?;
        let stored_clear = file.service == Some(crate::read::block::ServiceName::QuickOpen)
            && matches!(file.method, crate::types::Method::Stored)
            && !file.encrypted;
        if !stored_clear || common.data_size > self.policy.max_member_table {
            return None;
        }
        if self
            .ends_before(data_at.checked_add(common.data_size)?)
            .ok()?
        {
            return None;
        }
        let mut data = vec![0u8; usize::try_from(common.data_size).ok()?];
        if crate::read::cursor::read_upto_at(src, data_at, &mut data).ok()? != data.len() {
            return None;
        }
        Some(QuickOpen::Held {
            data,
            header_at: at,
            cursor: 0,
        })
    }

    /// True when the source ends before `at`, so a declared data area runs
    /// past what the set holds.
    fn ends_before(&self, at: u64) -> Result<bool> {
        if let Some(len) = self.cursor.source().len() {
            return Ok(at > len);
        }
        if at == 0 {
            return Ok(false);
        }
        let mut probe = [0u8; 1];
        Ok(crate::read::cursor::read_upto_at(self.cursor.source(), at - 1, &mut probe)? == 0)
    }

    /// What a walk that found no bytes at `pos` means: a clean end, or
    /// `Truncated` when the block before it declared data the source does
    /// not hold (spec F 3.5.5).
    fn at_source_end(&mut self) -> Result<Option<Block>> {
        // A diagnostic walk reports what it read and stops; truncation is
        // the reader's verdict, not the dump's.
        if !self.permissive
            && (self.overran || self.ends_before(self.pos)? || self.quick_open_cut_off())
        {
            return Err(Error::new(ErrorKind::Truncated).with_offset(self.pos));
        }
        self.done = true;
        Ok(None)
    }

    /// What `Truncated` from reading an ENCRYPTED header at `pos` means.
    /// With no byte at `pos` it is what a clear walk's empty read is, and
    /// [`Self::at_source_end`] rules. With bytes there and too few of them
    /// the archive is cut off inside a header, and that is `cut` itself:
    /// the clear path's verdict on the same cut.
    fn encrypted_header_cut(&mut self, cut: Error) -> Result<Option<Block>> {
        if !self.permissive && !self.cursor.peek_upto(self.pos, 1)?.is_empty() {
            return Err(cut);
        }
        self.at_source_end()
    }

    /// Note a data area the source does not hold.
    fn note_data(&mut self, end: u64) -> Result<()> {
        if self.ends_before(end)? {
            self.overran = true;
        }
        Ok(())
    }

    /// Append `bytes` to the name arena, bounded by the policy, and return
    /// its span.
    fn push_name(&mut self, from: std::ops::Range<usize>, decode: NameDecode) -> Result<()> {
        let start = self.arena.len();
        let limit = self.policy.max_member_table;
        {
            let BlockReader { head, arena, .. } = self;
            let field = head.get(from).ok_or_else(corrupt)?;
            match decode {
                NameDecode::Utf8 => arena.extend_from_slice(field),
                NameDecode::Legacy { unicode } => {
                    let at = arena.len();
                    crate::read::name4::decode_into(field, unicode, arena);
                    // RAR 1.3 through RAR 4 store a backslash between
                    // components whatever the host OS is; the reader
                    // converts it so one caller rule works for every format
                    // (spec F question 3). The stored bytes stay reachable
                    // through `blocks()`.
                    for byte in &mut arena[at..] {
                        if *byte == b'\\' {
                            *byte = b'/';
                        }
                    }
                }
            }
        }
        let needed = self.arena.len() as u64;
        if needed > limit {
            self.arena.truncate(start);
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::MemberTable,
                needed,
                limit,
            }));
        }
        Ok(())
    }

    fn name_span(&self, start: usize) -> std::ops::Range<u32> {
        start as u32..self.arena.len() as u32
    }

    /// What a RAR 5 header size over the policy's limit is.
    ///
    /// The limit's own error, as spec F 4.1 has it, for the block after
    /// the signature and for every caller that did not ask to read through
    /// damage. Under [`ReadOptions::read_damaged`] a LATER block that
    /// declares such a size is where a walk landed on bytes that are no
    /// header (a member in front declared too few packed bytes, say): a
    /// size that runs past the end of the source is `Truncated`, as every
    /// header the source ends inside is, and one that does not is
    /// `Corrupt`. Either leaves the members in front of it delivered.
    #[cold]
    fn oversized_rar5(&self, over: Error, pos: u64, head_len: u64) -> Error {
        if !self.lenient || pos == self.sig_end {
            return over;
        }
        match pos.checked_add(head_len).map(|end| self.ends_before(end)) {
            Some(Ok(false)) => corrupt().with_offset(pos),
            Some(Err(e)) => e,
            _ => Error::new(ErrorKind::Truncated).with_offset(pos),
        }
    }

    fn check_header_limit(&self, size: u64) -> Result<()> {
        if size > self.policy.max_header {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::HeaderSize,
                needed: size,
                limit: self.policy.max_header,
            })
            .with_offset(self.pos));
        }
        Ok(())
    }
}

/// The caller-owned slot's file header, ready for a parser to fill.
///
/// The slot KEEPS its header between blocks, and that is the point: an
/// archive of 20,000 members walks 20,000 file headers in a row, so on all
/// but the first the discriminant is already `File` and this costs nothing
/// whatever. Only a CHANGE of block kind builds a fresh header, one move of
/// 296 bytes on a path that runs about twice per archive, where handing a
/// header out of the parser paid that move once per MEMBER.
///
/// Reusing the slot is safe because `rar5::parse_file_into` and
/// `rar4::parse_file_into` each write EVERY field of it, which their
/// exhaustive destructuring makes the compiler check.
fn file_slot(into: &mut Block) -> &mut FileHdr {
    if !matches!(into.fields, Fields::File(_)) {
        into.fields = Fields::File(FileHdr::empty());
    }
    match &mut into.fields {
        Fields::File(file) => file,
        // Assigned just above, so nothing else can be here.
        _ => unreachable!("the slot was just made a file header"),
    }
}

/// How a name field is decoded.
#[derive(Clone, Copy)]
enum NameDecode {
    /// RAR 5: UTF-8, forward slashes, left alone.
    Utf8,
    /// RAR 1.3 to RAR 4: possibly the two-part Unicode encoding, and the
    /// separator normalised.
    Legacy { unicode: bool },
}

impl BlockReader<'_, '_> {
    fn next_rar5(&mut self, into: &mut Block) -> Result<bool> {
        let pos = self.pos;
        let mut data_at;
        if let Some(HeaderCrypt::Rar5(keys)) = &self.crypt {
            // The keys are BORROWED: a copy per header was an allocation
            // and a zeroise for every header of the archive.
            // Through the walk's window, as a clear header is read: two
            // direct reads of the source per header were most of what a
            // header cost once its key schedule was held.
            let span = match self.ctx.headers.rar5_from(&mut self.cursor, pos, keys) {
                Ok(span) => span,
                Err(e) if matches!(e.kind(), ErrorKind::Truncated) => {
                    return self.encrypted_header_cut(e).map(|_| false)
                }
                Err(e) => return Err(e),
            };
            self.head.clear();
            self.head.extend_from_slice(self.ctx.headers.plain());
            data_at = span.end;
        } else {
            let mut prefix = [0u8; 4 + vint::MAX_VINT_BYTES];
            let got = {
                let seen = self.cursor.peek_upto(pos, prefix.len())?;
                prefix[..seen.len()].copy_from_slice(seen);
                seen.len()
            };
            if got == 0 {
                return self.at_source_end().map(|_| false);
            }
            let mut at = 4usize;
            let size = match vint::read(&prefix[..got], &mut at) {
                Some(size) => size,
                // The source ended inside the checksum, or inside a size
                // whose every byte there asks for one more: a cut inside a
                // header (spec F 3.2.7 E3), as a RAR 4 header cut inside
                // its fixed fields is.
                None if got < prefix.len()
                    && prefix[got.min(4)..got].iter().all(|&b| b & 0x80 != 0) =>
                {
                    return Err(Error::new(ErrorKind::Truncated).with_offset(pos + got as u64));
                }
                None => return Err(corrupt().with_offset(pos)),
            };
            self.declared = size;
            let head_len = (at as u64)
                .checked_add(size)
                .ok_or_else(|| corrupt().with_offset(pos))?;
            if let Err(over) = self.check_header_limit(head_len) {
                return Err(self.oversized_rar5(over, pos, head_len));
            }
            let head_len = usize::try_from(head_len).map_err(|_| corrupt())?;
            let BlockReader { cursor, head, .. } = self;
            let bytes = cursor.peek(pos, head_len)?;
            head.clear();
            head.extend_from_slice(bytes);
            data_at = pos + head_len as u64;
        }
        let (common, checksum_ok) = match rar5::parse_common(&self.head) {
            Ok(common) if rar5::header_checksum(&self.head) == common.crc => (common, true),
            parsed if self.permissive => (parsed.map_err(|e| e.with_offset(pos))?, false),
            // A header whose checksum fails is not used for anything, not
            // even its size, so the walk cannot continue past it (spec F
            // 4.6) - unless the caller asked to read through damage.
            parsed => {
                let (common, sound, copied_end) = self.damaged_rar5(parsed, pos)?;
                if let Some(end) = copied_end {
                    data_at = end;
                }
                (common, sound)
            }
        };
        // Spec F 3.2.3: the block after the signature is the main header,
        // or the archive encryption header when headers are encrypted.
        // Every genuine archive begins so, and the reference lists
        // nothing of one that does not.
        if pos == self.sig_end
            && !matches!(common.btype, rar5::TYPE_MAIN | rar5::TYPE_ENCRYPTION)
            && !self.permissive
        {
            return Err(corrupt().with_offset(pos));
        }
        let data = data_at..data_at + common.data_size;
        self.note_data(data.end)?;
        match common.btype {
            rar5::TYPE_MAIN => {
                // The locator counts from the main header AS STORED: behind
                // header encryption that is `pos`, the first byte of the
                // IV in front of it, and not the first byte after the
                // signature, where the encryption header stands (spec F
                // 3.2.8).
                into.fields = rar5::parse_main(&self.head, &common, pos)?;
                // The locator of a main header whose own checksum failed
                // is not used (spec F 3.2.8 rule 1, 4.6 rule 5).
                if let Fields::Main(main) = &into.fields {
                    self.quick_open_at = main
                        .locator
                        .filter(|_| checksum_ok)
                        .and_then(|locator| locator.quick_open);
                    self.main_at = pos;
                }
            }
            rar5::TYPE_FILE | rar5::TYPE_SERVICE => {
                // Parsed STRAIGHT INTO the caller's slot: no header is
                // moved on this path. See `file_slot`.
                let name = rar5::parse_file_into(&self.head, &common, data.start, file_slot(into))?;
                if common.btype == rar5::TYPE_FILE {
                    self.split_open = common.flags & rar5::HF_SPLIT_AFTER != 0;
                }
                // Never on a permissive walk: the block dump prints the
                // field the mark rides in.
                if !checksum_ok && self.lenient {
                    file_slot(into).mark_unsound();
                }
                let mark = self.arena.len();
                self.push_name(name, NameDecode::Utf8)?;
                file_slot(into).name = self.name_span(mark);
                // A redirection's target is carried in the arena beside
                // the name, verbatim (spec F 3.2.6.2): the header's bytes
                // are gone once the next block is read.
                if let Some(redirect) = file_slot(into).redirect {
                    let mark = self.arena.len();
                    self.push_name(redirect.target(), NameDecode::Utf8)?;
                    let span = self.name_span(mark);
                    if let Some(r) = file_slot(into).redirect.as_mut() {
                        r.target_start = span.start;
                        r.target_len = span.end - span.start;
                    }
                }
            }
            rar5::TYPE_END => {
                into.fields = rar5::parse_end(&self.head, &common)?;
                self.done = true;
            }
            rar5::TYPE_ENCRYPTION => {
                if !self.permissive {
                    let record = rar5::parse_archive_crypt(&self.head, &common)?;
                    let password = self.ctx.password()?.clone();
                    // RAR 5 answers "wrong password" from the check value
                    // BEFORE any header is decrypted (spec K 3.7.3), and a
                    // long password's second cut is tried on it (3.7.1).
                    let keys = self
                        .ctx
                        .keys
                        .rar5_judged(&password, &record.salt, record.log2, record.check.as_ref())?
                        .clone();
                    self.crypt = Some(HeaderCrypt::Rar5(Box::new(keys)));
                }
                into.fields = Fields::Encryption;
            }
            // Spec F 3.2.10 U1: a block of a type this reader does not use
            // is skipped by its header size and data size whatever its
            // flags. The flag the technical note calls "skip if unknown"
            // speaks to a program UPDATING an archive, not to a reader.
            _ => {
                into.fields = Fields::Other;
            }
        }
        // Spec F 3.2.8 rule 2 case a: a block of any kind that begins
        // where the locator says the quick open record is.
        if Some(pos) == self.quick_open_at {
            self.quick_open_met = true;
        }
        // The rest of the block goes in FIELD BY FIELD: assigning a whole
        // `Block` here copied the 312 byte fields area again, even where
        // the parser had just filled it in place.
        into.kind = block_kind(&into.fields, common.btype);
        into.header = pos..data_at;
        into.data = data;
        into.checksum_ok = checksum_ok;
        Ok(true)
    }

    fn next_rar4(&mut self, into: &mut Block) -> Result<bool> {
        // The marker block is the signature itself.
        if !self.started {
            self.started = true;
            let end = self.sig_end;
            *into = Block {
                kind: crate::read::BlockKind::Other(u64::from(rar4::T_MARKER)),
                header: self.start..end,
                data: end..end,
                fields: Fields::Marker,
                checksum_ok: true,
            };
            return Ok(true);
        }
        let pos = self.pos;
        let header_end = if matches!(self.crypt, Some(HeaderCrypt::Rar4)) {
            let ReadCtx {
                headers,
                keys,
                options,
                ..
            } = &mut *self.ctx;
            // Borrowed, not copied per header.
            let password = options
                .password
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::PasswordRequired))?;
            let span = match headers.rar4_from(&mut self.cursor, pos, password, keys) {
                Ok(span) => span,
                Err(e) if matches!(e.kind(), ErrorKind::Truncated) => {
                    return self.encrypted_header_cut(e).map(|_| false)
                }
                Err(e) => return Err(e),
            };
            self.head.clear();
            self.head.extend_from_slice(self.ctx.headers.plain());
            self.declared = u64::from(span.size);
            span.end
        } else {
            let mut prefix = [0u8; rar4::COMMON];
            let got = {
                let seen = self.cursor.peek_upto(pos, prefix.len())?;
                prefix[..seen.len()].copy_from_slice(seen);
                seen.len()
            };
            if got == 0 {
                return self.at_source_end().map(|_| false);
            }
            if got < rar4::COMMON {
                return Err(Error::new(ErrorKind::Truncated).with_offset(pos + got as u64));
            }
            let size = u64::from(u16::from_le_bytes([prefix[5], prefix[6]]));
            self.declared = size;
            if size < rar4::COMMON as u64 {
                return Err(corrupt().with_offset(pos));
            }
            let BlockReader { cursor, head, .. } = self;
            let bytes = cursor.peek(pos, size as usize)?;
            head.clear();
            head.extend_from_slice(bytes);
            pos + size
        };
        let common = rar4::parse_common(&self.head).map_err(|e| e.with_offset(pos))?;
        let mut checksum_ok = rar4::header_checksum(&self.head, &common) == common.crc;
        if !checksum_ok && common.btype == rar4::T_SUB_OLD && self.crypt.is_none() {
            // The OLD subblock (3.3.3), which this package skips: its
            // checksum covers its data area as well as its header.
            // OBSERVED on the corpus's `external/rar2_unix_owner.rar`,
            // whose UOWNER block of 18 header bytes and 8 data bytes has
            // the checksum of exactly those 26 bytes and of no prefix of
            // them. The old recovery record beside it (0x78, 26 header
            // bytes and 514 or 2,962 data bytes on
            // `rar250_protect_head_rr1.rar` and `..._rr5.rar`) does NOT do
            // this: its checksum is its header's alone, so the rule is this
            // type's and not "every block with data". One archive, so it is
            // not confirmed on a second yet; the cost of
            // being wrong is accepting a skipped block rather than
            // rejecting the archive it sits in.
            let want = usize::from(common.size)
                .saturating_add(usize::try_from(common.data_size).unwrap_or(usize::MAX));
            if common.data_size <= rar4::SUB_OLD_CHECKSUM_MAX {
                let bytes = self.cursor.peek(pos, want)?;
                checksum_ok = crate::checksum::crc32(&bytes[2..want]) as u16 == common.crc;
            }
        }
        // Spec F 3.3.3 B2: a block of type 0x75 standing between blocks.
        // Its checksum covers offsets 2 to 12 of the block, the eleven
        // bytes after the checksum field, whatever its header size says,
        // so a header under 13 bytes never fits. One that fits is passed
        // over (rule 1). Any other is a header whose checksum failed and
        // nothing more (rule 2): 4.6's rule below reports it, and where
        // the walk goes on it is passed over the same way. The comment
        // blocks genuine writers make are inside a main or a file header
        // and never reach this.
        let lone_comment = common.btype == rar4::T_COMMENT && !self.permissive;
        if lone_comment {
            checksum_ok = self
                .head
                .get(2..rar4::LONE_COMMENT_CHECKED)
                .is_some_and(|checked| crate::checksum::crc32(checked) as u16 == common.crc);
        }
        // Read all the same under `ReadOptions::read_damaged`, where it is
        // clear: the reference reads a header whose checksum alone fails
        // (`<name> - the file header is corrupt`). An enciphered header
        // that fails is a wrong key and is never read.
        if !checksum_ok && !self.permissive {
            if !(self.lenient && self.crypt.is_none()) {
                return Err(Error::new(ErrorKind::HeaderChecksum).with_offset(pos));
            }
            self.unsound_read += 1;
        }
        // Spec F 3.3.3 B4: the block after the signature is the main
        // header, in every genuine archive and every volume of a set.
        if pos == self.sig_end && common.btype != rar4::T_MAIN && !self.permissive {
            return Err(corrupt().with_offset(pos));
        }
        let mut data = header_end..header_end + common.data_size;
        match common.btype {
            rar4::T_MAIN => {
                into.fields = rar4::parse_main(&self.head, &common, pos)?;
                if let Fields::Main(main) = &into.fields {
                    if main.headers_encrypted && !self.permissive {
                        // Every block after the main header is encrypted;
                        // the signature and the main header stay clear.
                        self.ctx.password()?;
                        self.crypt = Some(HeaderCrypt::Rar4);
                    }
                }
            }
            rar4::T_FILE | rar4::SERVICE_BLOCK => {
                // Parsed STRAIGHT INTO the caller's slot: no header is
                // moved on this path. See `file_slot`.
                let (name, unicode) =
                    rar4::parse_file_into(&self.head, &common, pos, file_slot(into))?;
                // The packed size is 64 bits of the producer's choosing
                // (its high half rides flag 0x0100), so the sum is checked:
                // an end past the top of a u64 is data the source does not
                // hold, never an end that wrapped to before the header.
                let data_end = header_end
                    .checked_add(file_slot(into).packed_size)
                    .ok_or_else(|| Error::new(ErrorKind::Truncated).with_offset(pos))?;
                data = header_end..data_end;
                if common.btype == rar4::T_FILE {
                    self.split_open = file_slot(into).split_after;
                }
                // Never on a permissive walk: the block dump prints the
                // field the mark rides in.
                if !checksum_ok && self.lenient {
                    file_slot(into).mark_unsound();
                }
                let mark = self.arena.len();
                self.push_name(name, NameDecode::Legacy { unicode })?;
                file_slot(into).name = self.name_span(mark);
            }
            rar4::T_END => {
                into.fields = rar4::parse_end(&self.head, &common)?;
                self.done = true;
            }
            // The old-style protect block is this family's recovery record;
            // spec L owns its content.
            rar4::OLD_RECOVERY_RECORD => into.fields = Fields::Other,
            // Spec F 3.3.3 B2: a lone comment block, whether its checksum
            // fit or it was read through a failed one, ends at its HEADER
            // SIZE. Flag 0x8000 and a data length are not honoured for
            // this type, so the next block is read at the first byte
            // after the header, never further.
            rar4::T_COMMENT if lone_comment => {
                into.fields = Fields::Other;
                data = header_end..header_end;
            }
            rar4::T_COMMENT | rar4::TYPE_76 | rar4::T_SUB_OLD | rar4::TYPE_79 => {
                into.fields = Fields::Other
            }
            // Spec F 3.3.3 B1: any other type is skipped by its header
            // size and data length, with flag 0x4000 or without it.
            _ => {
                into.fields = Fields::Other;
            }
        }
        self.note_data(data.end)?;
        // Field by field into the caller's slot, as in `next_rar5`.
        into.kind = match (&into.fields, common.btype) {
            (Fields::Other, rar4::OLD_RECOVERY_RECORD) => {
                crate::read::BlockKind::Service(crate::read::ServiceKind::RecoveryRecord)
            }
            // A lone comment block that was passed over is no comment a
            // caller is shown (spec F 3.3.3 B2): its text is not reported.
            (Fields::Other, rar4::T_COMMENT) if !lone_comment => {
                crate::read::BlockKind::Service(crate::read::ServiceKind::Comment)
            }
            (f, t) => block_kind(f, u64::from(t)),
        };
        into.header = pos..header_end;
        into.data = data;
        into.checksum_ok = checksum_ok;
        Ok(true)
    }

    fn next_rar13(&mut self, into: &mut Block) -> Result<bool> {
        let pos = self.pos;
        if !self.started {
            self.started = true;
            let mut prefix = [0u8; 64];
            let got = {
                let seen = self.cursor.peek_upto(pos, prefix.len())?;
                prefix[..seen.len()].copy_from_slice(seen);
                seen.len()
            };
            if got < rar13::ARCHIVE_FIXED {
                return Err(Error::new(ErrorKind::Truncated).with_offset(pos + got as u64));
            }
            let size = u64::from(u16::from_le_bytes([prefix[4], prefix[5]]));
            self.declared = size;
            self.check_header_limit(size)?;
            let BlockReader { cursor, head, .. } = self;
            let bytes = cursor.peek(pos, size.max(rar13::ARCHIVE_FIXED as u64) as usize)?;
            head.clear();
            head.extend_from_slice(bytes);
            let (header, fields) = rar13::parse_archive(&self.head, pos)?;
            let end = pos + u64::from(header.size);
            *into = Block {
                kind: crate::read::BlockKind::Main,
                header: pos..end,
                data: end..end,
                fields,
                checksum_ok: true,
            };
            return Ok(true);
        }
        let mut prefix = [0u8; rar13::FILE_FIXED];
        let got = {
            let seen = self.cursor.peek_upto(pos, prefix.len())?;
            prefix[..seen.len()].copy_from_slice(seen);
            seen.len()
        };
        if got == 0 {
            return self.at_source_end().map(|_| false);
        }
        if got < rar13::FILE_FIXED {
            return Err(Error::new(ErrorKind::Truncated).with_offset(pos + got as u64));
        }
        let size = u64::from(u16::from_le_bytes([prefix[10], prefix[11]]));
        self.declared = size;
        if size < rar13::FILE_FIXED as u64 {
            return Err(corrupt().with_offset(pos));
        }
        self.check_header_limit(size)?;
        let BlockReader { cursor, head, .. } = self;
        let bytes = cursor.peek(pos, size as usize)?;
        head.clear();
        head.extend_from_slice(bytes);
        let parsed = rar13::parse_file(&self.head, pos)?;
        let mark = self.arena.len();
        self.push_name(parsed.name, NameDecode::Legacy { unicode: false })?;
        let mut file = parsed.fields;
        file.name = self.name_span(mark);
        let header_end = pos + u64::from(parsed.header_size);
        let data = header_end..header_end + file.packed_size;
        self.note_data(data.end)?;
        *into = Block {
            kind: crate::read::BlockKind::File,
            header: pos..header_end,
            data,
            fields: Fields::File(file),
            checksum_ok: true,
        };
        Ok(true)
    }
}

/// The public block kind for `fields`, naming the raw type for a block no
/// variant covers.
fn block_kind(fields: &Fields, raw_type: u64) -> crate::read::BlockKind {
    match fields {
        Fields::Other | Fields::Marker => crate::read::BlockKind::Other(raw_type),
        other => other.kind(),
    }
}
