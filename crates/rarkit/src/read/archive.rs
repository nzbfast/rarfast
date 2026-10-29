//! Layer 2, the archive: one volume's headers, parsed to that volume's end
//! (spec F 2.2 and 3.7.4).
//!
//! Names live in ONE byte arena that grows geometrically; the member table
//! is ONE vector of fixed-size records holding offsets into the arena. No
//! allocation per member and none per name, and no seek per header: the
//! walk is forward-only through the read buffer and the only jumps are over
//! data areas.

use std::sync::Arc;

use crate::error::{Error, ErrorKind, Resource, Result};
use crate::read::block::{Block, CommentCodec, CommentSpan, Fields, Redirect, ServiceName};
use crate::read::cursor::read_exact_at;
use crate::read::detect;
use crate::read::reader::{BlockReader, ReadCtx};
use crate::read::{BlockInfo, Format, MemberInfo, ReadOptions, VolumeInfo};
use crate::source::RangeSource;
use crate::types::{Checksum, HostOs, Method, Timestamp};

/// One member of the table. Fixed size, with the name as a span of the
/// arena: this is where the old engine's 16.8 MiB for 20,000 members went,
/// and 4 MiB for 20,000 is about 200 bytes per member all in (spec F 7.3.7).
#[derive(Clone)]
struct MemberRec {
    name_start: u32,
    name_len: u32,
    header_start: u64,
    data_start: u64,
    packed_size: u64,
    unpacked_size: u64,
    mtime_seconds: i64,
    mtime_nanos: u32,
    attributes: u32,
    crc32: u32,
    /// Index into the archive's BLAKE2sp digests, or `u32::MAX`.
    blake: u32,
    /// The method code as stored, normalised so 0 is always "stored".
    method_code: u8,
    /// The dictionary size as its base-2 logarithm, which is exact for
    /// every size either format can name and costs one byte instead of
    /// eight. Zero means the member names no dictionary, which no real
    /// size can say: a one-byte dictionary does not exist.
    dict_log2: u8,
    unpack_version: u8,
    host_os: HostOs,
    flags: u16,
}

const M_DIRECTORY: u16 = 0x0001;
const M_SPLIT_BEFORE: u16 = 0x0002;
const M_SPLIT_AFTER: u16 = 0x0004;
const M_ENCRYPTED: u16 = 0x0008;
const M_SOLID: u16 = 0x0010;
const M_HAS_UNPACKED: u16 = 0x0020;
const M_HAS_MTIME: u16 = 0x0040;
const M_HAS_CRC32: u16 = 0x0080;
/// The member declares no dictionary at all: a directory entry, whose
/// RAR 1.5 to 4.x bits hold the marker value 7 instead of a size.
const M_NO_DICT: u16 = 0x0100;
/// The member is a symbolic link, hard link or file copy (spec F 3.2.6.2):
/// its record is in the archive's side table, found by the member's index.
/// A flag and not an index field, so a member that is not one pays nothing
/// (`tests::a_member_record_is_small_enough_for_the_ceiling`).
const M_REDIRECT: u16 = 0x0200;
/// The member carries a password check record (`MemberInfo::
/// password_checked`).
const M_CHECKED: u16 = 0x0400;

/// Where the dictionary's FRACTION sits in `flags`: five bits, 11 to 15.
/// Every dictionary either format names is `2^k * (32 + f) / 32` with `f`
/// below 32, and `f` is non-zero only for a RAR 5 version 1 member (spec F
/// 3.2.6.3), so the log beside it and these five bits hold it exactly
/// without growing the record past its gate.
const M_DICT_FRACTION_SHIFT: u16 = 11;

/// A dictionary as its log and its fraction in 32nds of that power.
fn dict_split(dictionary: u64) -> (u8, u16) {
    let dictionary = dictionary.max(1);
    let log2 = dictionary.ilog2();
    let step = (1u64 << log2) >> 5;
    let fraction = (dictionary - (1u64 << log2)).checked_div(step).unwrap_or(0);
    (log2 as u8, (fraction as u16) & 0x1F)
}

/// The inverse of [`dict_split`].
fn dict_join(log2: u8, fraction: u16) -> u64 {
    let base = 1u64 << log2;
    base + (base >> 5) * u64::from(fraction)
}

impl MemberRec {
    /// `redirect` is this member's record when it has one: the caller
    /// looks it up by the member's index, the only thing that knows it.
    fn info<'a>(
        &self,
        arena: &'a [u8],
        blakes: &'a [[u8; 32]],
        redirect: Option<&Redirect>,
        file_version: Option<crate::read::FileVersion>,
    ) -> MemberInfo<'a> {
        let name = self.name_start as usize..(self.name_start + self.name_len) as usize;
        MemberInfo {
            name: &arena[name],
            is_directory: self.flags & M_DIRECTORY != 0,
            unpacked_size: (self.flags & M_HAS_UNPACKED != 0).then_some(self.unpacked_size),
            packed_size: self.packed_size,
            split_before: self.flags & M_SPLIT_BEFORE != 0,
            split_after: self.flags & M_SPLIT_AFTER != 0,
            encrypted: self.flags & M_ENCRYPTED != 0,
            password_checked: self.flags & M_CHECKED != 0,
            mtime: (self.flags & M_HAS_MTIME != 0).then_some(Timestamp {
                unix_seconds: self.mtime_seconds,
                nanos: self.mtime_nanos,
            }),
            attributes: self.attributes,
            host_os: self.host_os,
            checksum: if self.blake != u32::MAX {
                Some(Checksum::Blake2sp(blakes[self.blake as usize]))
            } else if self.flags & M_HAS_CRC32 != 0 {
                Some(Checksum::Crc32(self.crc32))
            } else {
                None
            },
            method: if self.method_code == 0 {
                Method::Stored
            } else {
                Method::Compressed {
                    level: self.method_code,
                    dictionary: self.dictionary_bytes(),
                }
            },
            dictionary: self.dictionary(),
            solid: self.flags & M_SOLID != 0,
            algorithm_version: u32::from(self.unpack_version),
            data: self.data_start..self.data_start + self.packed_size,
            redirection: redirect.map(|r| {
                crate::read::Redirection {
                    kind: r.kind(),
                    // The RAR 4 family's target is its content, which a
                    // listing does not read (spec F 3.3.12).
                    target: (!r.in_content).then(|| arena.get(r.target()).unwrap_or(&[])),
                    target_is_directory: r.dir,
                }
            }),
            file_version,
        }
    }

    /// The dictionary size the header declares, whatever the method, and
    /// `None` where the member names none.
    fn dictionary(&self) -> Option<u64> {
        (self.flags & M_NO_DICT == 0).then(|| self.dictionary_bytes())
    }

    /// The dictionary the log and the fraction name, whether or not the
    /// member declares one.
    fn dictionary_bytes(&self) -> u64 {
        dict_join(self.dict_log2, self.flags >> M_DICT_FRACTION_SHIFT)
    }

    /// The member's own block, header and data area together.
    fn block(&self) -> BlockInfo {
        BlockInfo {
            kind: crate::read::BlockKind::File,
            range: self.header_start..self.data_start + self.packed_size,
        }
    }
}

/// One service record of the table: a `CMT`, `QO` or `RR` header, which is
/// NOT a member (spec F 3.2.9). There are one to three of these in an
/// archive of any size, so they are kept whole rather than packed the way
/// [`MemberRec`] is.
#[derive(Clone)]
struct ServiceRec {
    kind: crate::read::ServiceKind,
    /// How many members come before this record, which is what puts a
    /// listing's services and members back into archive order.
    before_member: u32,
    recovery_percent: Option<u32>,
    rec: MemberRec,
}

/// What reading one member holds besides its window and the walk's cursor:
/// the decoder tables and one copy buffer. Counted 29 Sep 2026: a 300 KB RAR 5
/// member read alone peaks at 1.4 MiB of engine working memory, its 1 MiB
/// floor ring included; 1 MiB covers the rest with room.
const ONE_MEMBER_FIXED: u64 = 1 << 20;

/// One volume, read.
///
/// Section 4.3 has [`Archive::open`] walk the volume as far as its end
/// record before it returns, so by the time a caller holds one of these
/// every question below is already answered out of memory and none of them
/// can fail or block. Nothing here mutates afterwards.
pub struct Archive {
    pub(crate) src: Arc<dyn RangeSource>,
    format: Format,
    start: u64,
    volume: VolumeInfo,
    solid: bool,
    headers_encrypted: bool,
    locked: bool,
    recovery: bool,
    comment: Option<Vec<u8>>,
    arena: Vec<u8>,
    members: Vec<MemberRec>,
    /// The service records, in archive order (spec F 3.2.9).
    services: Vec<ServiceRec>,
    blakes: Vec<[u8; 32]>,
    /// The redirection records of the members that carry one, with each
    /// member's index, in member order.
    redirects: Vec<(u32, Redirect)>,
    /// The members that are older versions of a file, by index in
    /// ascending order (spec F 3.2.6.4). Empty for every archive made
    /// without `-ver`, so a member that is not one pays one length test.
    versions: Vec<(u32, crate::read::FileVersion)>,
    /// Every block that is NOT a member's own, with the member index it
    /// comes before. A file block is derived from the member table instead
    /// of stored again: in an archive of 20,000 members those are all but
    /// two or three of the blocks, and storing them twice is 32 bytes a
    /// member against a 4 MiB ceiling (spec F 7.2, 7.3.7).
    other_blocks: Vec<(u32, BlockInfo)>,
    /// Bytes this archive has charged to the process-wide working-memory
    /// counter, released when it is dropped.
    charged: u64,
    /// Why the walk stopped short of the volume's end, when
    /// [`ReadOptions::tolerant_tail`] let it be kept rather than returned.
    tail: Option<Error>,
    /// The headers read although their own checksum failed
    /// ([`ReadOptions::read_damaged`]). Empty, and never allocated, on
    /// every archive whose headers are sound.
    damaged: Vec<crate::read::DamagedHeader>,
    /// The memory policy this archive was opened under, kept for work
    /// done FROM the archive later (a rewrite), which owes the caller the
    /// limit they named here.
    memory: crate::MemoryPolicy,
}

/// Which format a RAR 4 container's members make it: `Rar15` when every
/// member is 15 or below, `Rar20` when the highest is 20 or 26,
/// `Rar4Family` when any is 29 or above. A volume with no members at all is
/// `Rar4Family` (spec F 3.1.1).
pub(crate) fn refine_rar4(highest: Option<u32>) -> Format {
    match highest {
        None => Format::Rar4Family,
        Some(v) if v <= 15 => Format::Rar15,
        Some(20) | Some(26) => Format::Rar20,
        Some(v) if v < 29 => Format::Rar20,
        Some(_) => Format::Rar4Family,
    }
}

/// Find the signature, turning "no signature in range" into `NotAnArchive`
/// for a caller that required one.
pub(crate) fn require_signature(
    src: &dyn RangeSource,
    sfx_scan: u64,
) -> Result<crate::read::Found> {
    detect::detect_in(src, sfx_scan)?.ok_or_else(|| Error::new(ErrorKind::NotAnArchive))
}

impl Archive {
    /// Walk one volume's headers to its end record (or its end of file, for
    /// a container with no end record).
    pub(crate) fn open_with(src: Arc<dyn RangeSource>, ctx: &mut ReadCtx) -> Result<Archive> {
        let found = require_signature(src.as_ref(), ctx.options.sfx_scan)?;
        let mut archive = Archive {
            src: src.clone(),
            format: found.format,
            start: found.start,
            volume: VolumeInfo {
                is_volume: false,
                number: None,
                is_first: true,
                next_follows: None,
            },
            solid: false,
            headers_encrypted: false,
            locked: false,
            recovery: false,
            comment: None,
            arena: Vec::new(),
            members: Vec::new(),
            services: Vec::new(),
            blakes: Vec::new(),
            redirects: Vec::new(),
            versions: Vec::new(),
            other_blocks: Vec::new(),
            memory: ctx.options.memory,
            charged: 0,
            tail: None,
            damaged: Vec::new(),
        };
        let mut highest: Option<u32> = None;
        let mut first_member_split_before = None;
        let mut comment_span = None;
        // The CRC32 a RAR 5 comment's own header states over its text.
        let mut comment_crc32 = None;
        let table_limit = ctx.options.memory.max_member_table;
        let tolerant = ctx.options.tolerant_tail;
        {
            let mut reader = BlockReader::new(src.as_ref(), ctx, found.format, found.start);
            // One slot for every block of the volume, filled in place: a
            // block handed back by value is moved twice on its way here,
            // once per header.
            let mut slot = Block::empty();
            loop {
                // A walk that cannot reach the volume's end leaves the
                // members it already parsed valid (spec F 4.6). Without
                // `tolerant_tail` the reason is the open's, and with it the
                // reason is kept and the members are handed over: nothing
                // is parsed more permissively either way.
                let block = match reader.next_into(&mut slot) {
                    Ok(true) => &slot,
                    Ok(false) => {
                        // Damage behind a member that continues: the end
                        // record was not read, and the member's own header
                        // says another volume follows.
                        if reader.cut_after_split() {
                            archive.volume.next_follows = Some(true);
                        }
                        // Spec F 3.2.8 rule 2: the walk was made whole,
                        // and the locator's quick open offset is judged
                        // then: a lost tail, or a wrong locator.
                        if let Some(wrong) = reader.locator_verdict() {
                            if !tolerant {
                                return Err(wrong);
                            }
                            archive.tail = Some(wrong);
                        }
                        break;
                    }
                    Err(err) if tolerant && tail_stops_the_walk(&err) => {
                        archive.tail = Some(err);
                        break;
                    }
                    Err(err) => return Err(err),
                };
                if !block.checksum_ok {
                    let from_copy = reader.read_from_copy();
                    archive.note_damaged(block, from_copy);
                }
                if !matches!(block.kind, crate::read::BlockKind::File) {
                    let at = archive.members.len() as u32;
                    archive.other_blocks.push((
                        at,
                        BlockInfo {
                            kind: block.kind,
                            range: block.header.start..block.end(),
                        },
                    ));
                }
                match &block.fields {
                    Fields::Main(main) => {
                        archive.solid = main.solid;
                        archive.locked = main.locked;
                        archive.recovery |= main.recovery;
                        // RAR 4's flag; a RAR 5 archive has already said so
                        // by its encryption block, which this must not undo.
                        archive.headers_encrypted |= main.headers_encrypted;
                        archive.volume.is_volume = main.is_volume;
                        archive.volume.number = main.volume_number;
                        if let Some(c) = &main.comment {
                            comment_span = Some(c.clone());
                        }
                    }
                    Fields::File(file) => match file.service {
                        None => {
                            if first_member_split_before.is_none() {
                                first_member_split_before = Some(file.split_before);
                            }
                            highest =
                                Some(highest.map_or(file.unpack_version, |h: u32| {
                                    h.max(file.unpack_version)
                                }));
                            archive.push_member(block, file)?;
                        }
                        Some(name) => {
                            // A service block is not a member: it never
                            // reaches `members()` and `extract` never hands
                            // one to a sink. It is listed on its own,
                            // because a technical listing names it
                            // (spec F 3.2.9).
                            archive.push_service(block, file, name)?;
                            match name {
                                // Spec F 3.2.9 S3: in RAR 5 the comment is
                                // the FIRST `CMT` block met before any file
                                // header. One after the members is not the
                                // comment, and of two the first is.
                                ServiceName::Comment
                                    if matches!(found.format, Format::Rar5)
                                        && (comment_span.is_some()
                                            || !archive.members.is_empty()) => {}
                                ServiceName::Comment => {
                                    if matches!(found.format, Format::Rar5) {
                                        comment_crc32 = match file.checksum {
                                            Some(crate::types::Checksum::Crc32(crc)) => Some(crc),
                                            _ => None,
                                        };
                                    }
                                    // The RAW method code is NOT the test:
                                    // it is 0x30 for a STORED RAR 1.5 to
                                    // 4.x record and 0 for a RAR 5 one, and
                                    // comparing it against 0 reported no
                                    // comment on every RAR 4 archive that
                                    // has one.
                                    comment_span = Some(CommentSpan {
                                        data: block.data.clone(),
                                        unpacked: file.unpacked_size.unwrap_or(0),
                                        version: u8::try_from(file.unpack_version)
                                            .unwrap_or(u8::MAX),
                                        method: file.method_code as u8,
                                        codec: if matches!(found.format, Format::Rar5) {
                                            match file.method {
                                                Method::Stored => CommentCodec::Stored,
                                                // An unknown version names
                                                // no dictionary, and no
                                                // decoder runs for it.
                                                Method::Compressed { .. }
                                                    if file.dictionary.is_none() =>
                                                {
                                                    CommentCodec::Missing
                                                }
                                                Method::Compressed { .. } => CommentCodec::Rar5(
                                                    u8::try_from(file.unpack_version)
                                                        .unwrap_or(u8::MAX),
                                                ),
                                            }
                                        } else {
                                            crate::read::rar4::comment_codec(
                                                file.method_code as u8,
                                                file.unpack_version,
                                            )
                                        },
                                    });
                                }
                                ServiceName::Recovery => archive.recovery = true,
                                _ => {}
                            }
                        }
                    },
                    Fields::End(end) => {
                        archive.volume.next_follows = Some(end.next_follows);
                        if archive.volume.number.is_none() {
                            archive.volume.number = end.volume_number;
                        }
                    }
                    // RAR 5 enciphers every header after this block (spec F,
                    // `f08_hp.rar`); its main block carries no such flag.
                    Fields::Encryption => archive.headers_encrypted = true,
                    _ => {}
                }
                // The names are still the reader's until the walk ends.
                archive.check_budget(table_limit, reader.arena().len())?;
            }
            archive.arena = reader.take_arena();
        }
        // The member table and the arena are this package's whole working
        // set on the listing path; charge them so `memory::peak` answers
        // the RSS target of spec F 7.2 rather than the process's own
        // figure, which includes the caller's source.
        archive.charged = archive.working_bytes();
        crate::memory::charge(archive.charged);
        if !matches!(found.format, Format::Rar5 | Format::Rar13) {
            archive.format = refine_rar4(highest);
        }
        archive.volume.is_first = match found.format {
            // The main header's volume flag is set, and either the volume
            // number field is absent or it is 0.
            Format::Rar5 => !archive.volume.is_volume || archive.volume.number.unwrap_or(0) == 0,
            // Main header flag 0x0100 when the writer sets it (RAR 3 and
            // later), otherwise the volume whose first member header does
            // not carry the "continues from the previous volume" flag.
            // The RAR 1.5 to 4.x family: a volume is the first when
            // nothing in it continues from an earlier one. The main
            // header's 0x0100 flag is NOT the test, although 3.5.3 reads
            // it as one: genuine RAR 3.00 writes it on every volume of a
            // set (OBSERVED on `multivol_oldnaming_rar300.*` and
            // `multivol_newnaming_rar300.part0*`), so believing it makes
            // every continuation volume claim to be the first.
            _ => !first_member_split_before.unwrap_or(false),
        };
        if archive.volume.is_volume && archive.volume.number.is_none() && archive.volume.is_first {
            archive.volume.number = Some(0);
        }
        if let Some(span) = comment_span {
            archive.comment = archive.read_comment(&span, ctx);
            // Spec F 3.2.9 S3: a comment that fails the checksum its
            // header states is no comment, and never fails the open.
            if let (Some(text), Some(stated)) = (&archive.comment, comment_crc32) {
                if crate::checksum::crc32(text) != stated {
                    archive.comment = None;
                }
            }
            // And a RAR 5 comment's final zero byte is not part of the
            // text.
            if matches!(found.format, Format::Rar5) {
                if let Some(text) = archive.comment.as_mut() {
                    if text.last() == Some(&0) {
                        text.pop();
                    }
                }
            }
        }
        Ok(archive)
    }

    fn push_member(&mut self, block: &Block, file: &crate::read::block::FileHdr) -> Result<()> {
        let mut flags = 0u16;
        for (set, bit) in [
            (file.is_directory, M_DIRECTORY),
            (file.split_before, M_SPLIT_BEFORE),
            (file.split_after, M_SPLIT_AFTER),
            (file.encrypted, M_ENCRYPTED),
            (
                file.encrypted && file.crypt.as_ref().is_some_and(|c| c.check.is_some()),
                M_CHECKED,
            ),
            (file.solid, M_SOLID),
            (file.unpacked_size.is_some(), M_HAS_UNPACKED),
            (file.mtime.is_some(), M_HAS_MTIME),
        ] {
            if set {
                flags |= bit;
            }
        }
        let (crc32, blake) = match file.checksum {
            Some(Checksum::Crc32(v)) => {
                flags |= M_HAS_CRC32;
                (v, u32::MAX)
            }
            Some(Checksum::Blake2sp(digest)) => {
                self.blakes.push(digest);
                (0, (self.blakes.len() - 1) as u32)
            }
            None => (0, u32::MAX),
        };
        // One field for both readings: the DECLARED dictionary and the one
        // `Method::Compressed` carries are the same value read from the
        // same bits, so a member cannot list one size and decode with
        // another. The flag is what separates "names no dictionary" from
        // the window a directory entry's own method would use.
        let (method_code, (dict_log2, dict_fraction)) = match file.method {
            Method::Stored => (0u8, file.dictionary.map_or((0, 0), dict_split)),
            Method::Compressed { level, dictionary } => (level.max(1), dict_split(dictionary)),
        };
        flags |= dict_fraction << M_DICT_FRACTION_SHIFT;
        if file.dictionary.is_none() {
            flags |= M_NO_DICT;
        }
        // A service header never carries one: the parser ignores the record
        // there, so the flag cannot point a service at a member's entry.
        if let Some(r) = file.redirect {
            flags |= M_REDIRECT;
            self.redirects.push((self.members.len() as u32, r));
        }
        if let Some(version) = file.file_version() {
            self.versions.push((self.members.len() as u32, version));
        }
        let mtime = file.mtime.unwrap_or(Timestamp {
            unix_seconds: 0,
            nanos: 0,
        });
        self.members.push(MemberRec {
            name_start: file.name.start,
            name_len: file.name.end - file.name.start,
            header_start: block.header.start,
            data_start: block.data.start,
            packed_size: block.data.end - block.data.start,
            unpacked_size: file.unpacked_size.unwrap_or(0),
            mtime_seconds: mtime.unix_seconds,
            mtime_nanos: mtime.nanos,
            attributes: file.attributes,
            crc32,
            blake,
            method_code,
            dict_log2,
            unpack_version: u8::try_from(file.unpack_version).unwrap_or(u8::MAX),
            host_os: file.host_os,
            flags,
        });
        Ok(())
    }

    /// Record one service block: a `CMT`, `QO`, `RR` or other service
    /// header. Its fields take a file header's shape, because that is what
    /// the format gives it (spec F 3.2.9).
    fn push_service(
        &mut self,
        block: &Block,
        file: &crate::read::block::FileHdr,
        name: ServiceName,
    ) -> Result<()> {
        let before_member = self.members.len() as u32;
        let members = self.members.len();
        self.push_member(block, file)?;
        let rec = self.members.pop().expect("push_member pushed one");
        debug_assert_eq!(self.members.len(), members);
        self.services.push(ServiceRec {
            kind: name.kind(),
            before_member,
            recovery_percent: file.recovery_percent.map(std::num::NonZeroU32::get),
            rec,
        });
        Ok(())
    }

    /// The member table and the name arena share one budget, counted in
    /// bytes (spec F 4.2).
    fn working_bytes(&self) -> u64 {
        (self.members.capacity() * std::mem::size_of::<MemberRec>()) as u64
            + (self.services.capacity() * std::mem::size_of::<ServiceRec>()) as u64
            + self.arena.capacity() as u64
            + (self.other_blocks.capacity() * std::mem::size_of::<(u32, BlockInfo)>()) as u64
            + (self.blakes.capacity() * 32) as u64
            + (self.redirects.capacity() * std::mem::size_of::<(u32, Redirect)>()) as u64
            + std::mem::size_of_val(self.versions.as_slice()) as u64
    }

    /// The table against `limit` with `names` bytes of names beside it:
    /// one budget for both, not the whole limit for each (spec F 4.2).
    fn check_budget(&self, limit: u64, names: usize) -> Result<()> {
        let needed = (self.members.len() * std::mem::size_of::<MemberRec>()) as u64
            + names as u64
            + (self.other_blocks.len() * std::mem::size_of::<(u32, BlockInfo)>()) as u64;
        if needed > limit {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::MemberTable,
                needed,
                limit,
            }));
        }
        Ok(())
    }

    /// The archive comment, decoded when the codec is available.
    ///
    /// A comment whose unpacked size is above the limit, or whose method no
    /// decoder claims, is NOT an error: it is `None`, because a caller
    /// asked to open an archive and not to read a comment (spec F 3.2.9,
    /// 3.4.5, question 5).
    fn read_comment(&self, span: &CommentSpan, ctx: &ReadCtx) -> Option<Vec<u8>> {
        let len = span.data.end.checked_sub(span.data.start)?;
        let limit = ctx.options.memory.max_comment;
        if len == 0 || len > limit {
            return None;
        }
        // The DECODED size is bounded before anything is decoded, as well
        // as the packed one, because a comment's header declares it and a
        // caller asked to open an archive rather than to fill memory.
        if span.unpacked > limit {
            return None;
        }
        let mut packed = vec![0u8; len as usize];
        read_exact_at(self.src.as_ref(), span.data.start, &mut packed).ok()?;
        if matches!(span.codec, CommentCodec::Stored) {
            return Some(packed);
        }
        // A comment is a stream like a member's, so the same decoders
        // read it. What makes it easier than a member is that it is
        // bounded, never solid and never split, which is why it is driven
        // here rather than through the extract path. A comment that does
        // not decode is `None` and never an error: a caller asked to open
        // an archive, not to read a comment (spec F question 5).
        decode_comment(span, &packed)
    }

    /// The archive's format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// How many bytes sit in front of the archive, which for a
    /// self-extracting file is the executable stub and otherwise is 0.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// What this volume is within its set. Section 4.3 has one answer
    /// covering both families, which is why it is a struct and why two of
    /// its fields are optional: a format that does not record a volume
    /// number cannot be made to report one.
    pub fn volume(&self) -> VolumeInfo {
        self.volume
    }

    /// Whether members share one compression history, so that decoding a
    /// member means decoding the ones before it.
    pub fn is_solid(&self) -> bool {
        self.solid
    }

    /// Whether the block structure itself is enciphered, which is the case
    /// where even listing needs the password (section 4.5).
    pub fn headers_encrypted(&self) -> bool {
        self.headers_encrypted
    }

    /// Whether the producer marked the archive against modification.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Whether this volume carries repair data of its own, which is what
    /// [`crate::recovery::repair_inline`] works from.
    pub fn has_recovery_record(&self) -> bool {
        self.recovery
    }

    /// The memory policy this archive was opened under.
    pub(crate) fn memory(&self) -> &crate::MemoryPolicy {
        &self.memory
    }

    /// The archive comment, decoded.
    ///
    /// `None` when there is none, when it declares a method this build
    /// cannot decode, or when its unpacked size is above
    /// [`MemoryPolicy::max_comment`](crate::MemoryPolicy::max_comment).
    /// A comment never makes [`Archive::open`] fail: a caller asked to open
    /// an archive, not to read a comment (spec F question 5).
    pub fn comment(&self) -> Option<&[u8]> {
        self.comment.as_deref()
    }

    /// The least working memory a read of this archive can run in: the
    /// largest thing any ONE member needs at breadth one (its window as
    /// the member-sized rule prices it), plus what the walk itself holds
    /// whatever the member (this volume's header tables, the read-ahead,
    /// and a fixed floor for tables and one copy buffer), and at least
    /// the largest window any member reaches where the policy's
    /// `max_window` would refuse it, plus the policy's
    /// `process_overhead`, so the figure is in the terms of the
    /// constructor that built `policy`: engine working memory under
    /// [`MemoryPolicy::from_limit`](crate::MemoryPolicy::from_limit), the
    /// whole process under
    /// [`MemoryPolicy::for_process`](crate::MemoryPolicy::for_process)
    /// (SPEC-API 8.4.1).
    ///
    /// A read under a NAMED budget below this is refused before any member
    /// with `LimitExceeded { resource: WorkingMemory }`. It covers this
    /// volume's members; for a set, the caller takes the largest over the
    /// volumes it has.
    pub fn minimum_working_memory(&self, policy: &crate::MemoryPolicy) -> u64 {
        let one_member = self
            .largest_member_need(policy)
            .saturating_add(self.fixed_working_memory(policy));
        // Every window a member reaches must also fit under `max_window`,
        // or that member is refused (promise 2.3). A budget built by
        // `from_limit` or `for_process` derives `max_window` as its
        // engine limit (SPEC-API 8.4.1, the account's item 4), so where
        // this policy's window is too small the minimum is at least the
        // largest reach.
        let reach = self
            .members()
            .map(|member| crate::read::extract::member_reach(&member, self.format, self.solid))
            .max()
            .unwrap_or(0);
        let for_window = if reach > policy.max_window { reach } else { 0 };
        one_member
            .max(for_window)
            .saturating_add(policy.process_overhead)
    }

    /// What the walk holds whatever member it is on, in engine working
    /// memory: this volume's header tables, the policy's read-ahead and
    /// the fixed floor for tables and one copy buffer. What a NAMED
    /// budget leaves above this is the room the members in flight share
    /// for their windows, and the pools admit each member against it by
    /// its own need (SPEC-API 8.4.1, the pre-scan).
    pub(crate) fn fixed_working_memory(&self, policy: &crate::MemoryPolicy) -> u64 {
        self.working_bytes()
            .saturating_add(policy.read_ahead)
            .saturating_add(ONE_MEMBER_FIXED)
    }

    /// The most any one member of this volume needs for its window
    /// ([`crate::read::extract::member_need`]).
    pub(crate) fn largest_member_need(&self, policy: &crate::MemoryPolicy) -> u64 {
        self.members()
            .map(|member| {
                crate::read::extract::member_need(
                    &member,
                    self.format,
                    self.solid,
                    policy.max_window,
                )
            })
            .max()
            .unwrap_or(0)
    }

    /// The members, in archive order. Borrows the name arena; allocates
    /// nothing.
    pub fn members(&self) -> impl ExactSizeIterator<Item = MemberInfo<'_>> {
        self.members.iter().enumerate().map(|(index, rec)| {
            let redirect = (rec.flags & M_REDIRECT != 0)
                .then(|| {
                    let at = self
                        .redirects
                        .binary_search_by_key(&(index as u32), |r| r.0);
                    at.ok().map(|at| &self.redirects[at].1)
                })
                .flatten();
            let version = (!self.versions.is_empty())
                .then(|| {
                    let at = self.versions.binary_search_by_key(&(index as u32), |v| v.0);
                    at.ok().map(|at| self.versions[at].1)
                })
                .flatten();
            rec.info(&self.arena, &self.blakes, redirect, version)
        })
    }

    /// The service records, in archive order.
    ///
    /// A service block is NOT a member: it never appears in
    /// [`Archive::members`] and `extract` never hands one to a
    /// [`Sink`](crate::Sink). It is here because a technical listing names
    /// it - reference `unrar lta` prints a `CMT`, `QO` or `RR` entry with
    /// its own sizes and compression clause, in archive order among the
    /// members, which [`ServiceInfo::before_member`] puts back.
    ///
    /// [`ServiceInfo::before_member`]: crate::ServiceInfo::before_member
    pub fn services(&self) -> impl ExactSizeIterator<Item = crate::read::ServiceInfo<'_>> {
        self.services.iter().map(|svc| crate::read::ServiceInfo {
            kind: svc.kind,
            header: svc.rec.info(&self.arena, &self.blakes, None, None),
            before_member: svc.before_member,
            recovery_percent: svc.recovery_percent,
        })
    }

    /// Why this volume's walk stopped short of its end, when
    /// [`ReadOptions::tolerant_tail`] was set and it did.
    ///
    /// `None` on an archive that was walked to its end record or its end of
    /// file, which is every archive opened without that option: without it
    /// the same condition is the open's own error (spec F 3.5.5, 4.6). The
    /// members and services this archive carries are the ones parsed before
    /// it, and every one of them is as valid as it would have been in an
    /// undamaged archive.
    pub fn tail(&self) -> Option<&Error> {
        self.tail.as_ref()
    }

    /// The headers of this volume that were read although their own
    /// checksum failed, in the order they sit on disk.
    ///
    /// Empty unless [`ReadOptions::read_damaged`] was set: without it such
    /// a header ends the walk (spec F 4.6). With it, each is a header the
    /// reference reads too and reports (`<name> - the file header is
    /// corrupt`, `Main archive header is corrupt`), and a caller that
    /// wants to say "this archive is damaged" reads this beside
    /// [`Archive::tail`]: a member behind such a header is extracted and
    /// checked against the checksum that header states, so its own
    /// outcome can be good.
    ///
    /// At most [`DAMAGED_HEADERS_KEPT`](crate::read::DAMAGED_HEADERS_KEPT)
    /// are kept, the first ones: a volume with more is read on all the
    /// same, and is as damaged as its first entry says.
    pub fn damaged_headers(&self) -> &[crate::read::DamagedHeader] {
        &self.damaged
    }

    /// Record a block read from a header whose checksum failed. A file
    /// block is noted BEFORE its member is pushed, so the index it names
    /// is the one that member is about to take.
    #[cold]
    fn note_damaged(&mut self, block: &crate::read::block::Block, from_copy: bool) {
        let member = match &block.fields {
            Fields::File(file) if file.service.is_none() => Some(self.members.len()),
            _ => None,
        };
        // Every one costs the caller a line and this table an entry, and
        // an archive of nothing but such headers is an attacker's: past
        // the cap the walk goes on and the table does not.
        if self.damaged.len() >= crate::read::DAMAGED_HEADERS_KEPT {
            return;
        }
        self.damaged.push(crate::read::DamagedHeader {
            kind: block.kind,
            range: block.header.clone(),
            member,
            from_copy,
        });
    }

    /// Walk the volume's blocks in the order they sit on disk.
    ///
    /// Section 4.3 makes this the ONE place either family's header layout
    /// shows through, and even here it shows only as the shared
    /// [`crate::BlockKind`]. It is what a fuzz seed generator, a test that
    /// asks where a recovery record landed, and a technical listing need.
    ///
    /// The quick open record appears here and is used for nothing: it is a
    /// second copy of data whose first copy is authoritative, written by
    /// the archive's producer, so an archive whose cached headers disagree
    /// with its real ones cannot be made to list one thing and extract
    /// another (spec F question 4).
    pub fn blocks(&self) -> impl Iterator<Item = BlockInfo> + '_ {
        Blocks {
            archive: self,
            member: 0,
            other: 0,
        }
    }

    /// The source these bytes were read from, to hand to a call that wants
    /// the same volume again.
    pub fn source(&self) -> &Arc<dyn RangeSource> {
        &self.src
    }
}

/// Whether an error is one that ends a walk at the volume's TAIL rather
/// than one that says nothing was read at all.
///
/// `Truncated` is a source that ended inside a header or a data area
/// (spec F 3.5.5), `HeaderChecksum` and `Corrupt` are damage the walk
/// cannot step over (4.6): each leaves the members in front of it intact
/// and each is what reference `unrar l` keeps listing through. Everything
/// else - no signature, a password, a limit, a source error, a cancel -
/// says the archive was never readable, and a tolerant tail does not
/// change that.
fn tail_stops_the_walk(err: &Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Truncated | ErrorKind::HeaderChecksum | ErrorKind::Corrupt(_)
    )
}

/// A throwaway-session open (API section 4.3).
pub(crate) fn open_archive(src: Arc<dyn RangeSource>, opts: &ReadOptions) -> Result<Archive> {
    let mut ctx = ReadCtx::new(opts.clone());
    Archive::open_with(src, &mut ctx)
}

/// One of the two helpers that open a path the CALLER named.
pub(crate) fn open_archive_path(path: &std::path::Path, ctx: &mut ReadCtx) -> Result<Archive> {
    let file = std::fs::File::open(path).map_err(|e| Error::new(ErrorKind::Source(e)))?;
    Archive::open_with(Arc::new(file), ctx)
}

impl Drop for Archive {
    fn drop(&mut self) {
        crate::memory::release(self.charged);
    }
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("format", &self.format)
            .field("start", &self.start)
            .field("volume", &self.volume)
            .field("solid", &self.solid)
            .field("headers_encrypted", &self.headers_encrypted)
            .field("members", &self.members.len())
            .field("blocks", &(self.members.len() + self.other_blocks.len()))
            .finish()
    }
}

/// The block sequence: every block that is not a member's own, merged with
/// the member blocks the table already holds, in archive order.
struct Blocks<'a> {
    archive: &'a Archive,
    member: usize,
    other: usize,
}

impl Iterator for Blocks<'_> {
    type Item = BlockInfo;

    fn next(&mut self) -> Option<BlockInfo> {
        if let Some((at, info)) = self.archive.other_blocks.get(self.other) {
            if *at as usize <= self.member {
                self.other += 1;
                return Some(info.clone());
            }
        }
        let rec = self.archive.members.get(self.member)?;
        self.member += 1;
        Some(rec.block())
    }
}

/// One comment's packed bytes, decoded by the algorithm its header names.
///
/// The window is sized from the comment's own DECLARED size rather than
/// from the format's maximum: a match can never reach further back than
/// the bytes already produced, so a window that covers the output covers
/// every distance in it, and the alternative is allocating a format's
/// widest dictionary to read a line of text on every `open`.
fn decode_comment(span: &CommentSpan, packed: &[u8]) -> Option<Vec<u8>> {
    /// The smallest window any of these decoders is asked for.
    const FLOOR: u64 = 64 << 10;
    let unpacked = span.unpacked;
    if unpacked == 0 {
        return None;
    }
    let window = u32::try_from(unpacked.max(FLOOR).next_power_of_two()).ok()?;
    let out = match span.codec {
        CommentCodec::Stored => return Some(packed.to_vec()),
        CommentCodec::Missing => return None,
        CommentCodec::Rar15 => {
            let mut lz = crate::rar1x::Rar1x::new();
            let mut source = crate::rar5_lz::SliceSource::new(packed);
            let mut out: Vec<u8> = Vec::with_capacity(unpacked as usize);
            lz.member(&mut source, unpacked, false, &mut out).ok()?;
            out
        }
        CommentCodec::Rar20 => crate::lz20::Rar20Chain::new(window)
            .decode_next(packed, unpacked)
            .ok()?,
        CommentCodec::Rar29 => {
            let policy = crate::memory::MemoryPolicy::default();
            let mut stream = crate::rar3_lz::Rar3Stream::new(window, &policy).ok()?;
            let mut bits = crate::rar3_lz::bits::Bits::new(packed);
            /// A `StreamOut` that keeps the bytes.
            struct Keep(Vec<u8>);

            impl crate::rar3_lz::StreamOut for Keep {
                fn write(&mut self, bytes: &[u8]) -> Result<()> {
                    self.0.extend_from_slice(bytes);
                    Ok(())
                }
            }

            let mut out = Keep(Vec::with_capacity(unpacked as usize));
            stream
                .member(
                    &mut bits,
                    &crate::rar3_lz::MemberSpan {
                        packed: 0..packed.len(),
                        unpacked,
                    },
                    &mut out,
                )
                .ok()?;
            out.0
        }
        CommentCodec::Rar5(algorithm) => {
            let policy = crate::memory::MemoryPolicy::default();
            let mut lz = crate::rar5_lz::Rar5Lz::new(u64::from(window), &policy).ok()?;
            let mut source = crate::rar5_lz::SliceSource::new(packed);
            let mut out: Vec<u8> = Vec::with_capacity(unpacked as usize);
            lz.member(&mut source, unpacked, algorithm, &mut out).ok()?;
            out
        }
    };
    (out.len() as u64 == unpacked).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::MemberRec;

    /// Spec F 7.3.7: one allocation's worth of fixed-size records, and
    /// 4 MiB for 20,000 members is about 200 bytes per member all in. The
    /// record is the bulk of that, so its size is a gate of its own.
    /// Every dictionary a RAR 5 version 1 member can declare (spec F
    /// 3.2.6.3), and every power of two either format names, comes back
    /// from the index exactly as the walk read it.
    #[test]
    fn the_index_keeps_every_dictionary_exactly() {
        for power in 0..=31u32 {
            for fraction in 0..32u64 {
                let base = (128u64 * 1024) << power;
                let dictionary = base + (base / 32) * fraction;
                let (log2, frac) = super::dict_split(dictionary);
                assert_eq!(super::dict_join(log2, frac), dictionary);
            }
        }
        for log2 in 0..40u32 {
            let (l, f) = super::dict_split(1u64 << log2);
            assert_eq!(super::dict_join(l, f), 1u64 << log2);
        }
    }

    #[test]
    fn a_member_record_is_small_enough_for_the_ceiling() {
        assert!(
            std::mem::size_of::<MemberRec>() <= 72,
            "MemberRec is {} bytes",
            std::mem::size_of::<MemberRec>()
        );
    }
}
