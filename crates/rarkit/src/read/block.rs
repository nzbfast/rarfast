//! The block model the three container generations share (spec F 2.1).
//!
//! A block is `{ kind, header range, data range, fields }` with both ranges
//! in SOURCE coordinates. Names are not owned here: a parsed name is a span
//! of the reader's one name arena, so nothing allocates per member.

use std::ops::Range;

use crate::read::{BlockKind, ServiceKind};
use crate::types::{Checksum, HostOs, Method, Timestamp};

/// A span of the reader's name arena.
pub(crate) type NameSpan = Range<u32>;

/// One parsed block.
#[derive(Clone)]
pub(crate) struct Block {
    /// What the block is, as the public API names it.
    pub kind: BlockKind,
    /// The header's bytes, in source coordinates.
    pub header: Range<u64>,
    /// The data area's bytes, in source coordinates; empty when there is
    /// none. For an encrypted header this is the area after the ciphertext.
    pub data: Range<u64>,
    /// The type-specific fields.
    pub fields: Fields,
    /// False when the header's own checksum did not match. Only a
    /// permissive walk and one under `ReadOptions::read_damaged` ever see
    /// this: any other stops instead (spec F 4.6).
    pub checksum_ok: bool,
}

impl Block {
    /// A block that names nothing, for a caller that owns the slot the
    /// reader fills.
    ///
    /// `Block` is 352 bytes and costs that much every time it is moved.
    /// Returning one by value from the reader and again from the walk
    /// compiled to TWO `memcpy` calls of 0x160 bytes per block, read off
    /// the release disassembly on 22 Sep 2026, on a path that runs once
    /// per member; a caller-owned slot is how those go away.
    pub(crate) fn empty() -> Block {
        Block {
            kind: BlockKind::Other(0),
            header: 0..0,
            data: 0..0,
            fields: Fields::Other,
            checksum_ok: true,
        }
    }

    /// The first byte after this block, header and data area together.
    pub(crate) fn end(&self) -> u64 {
        self.data.end.max(self.header.end)
    }
}

/// The type-specific fields of a block.
#[derive(Clone)]
pub(crate) enum Fields {
    /// The RAR 1.5 to 4.x marker block, which is the signature itself.
    Marker,
    /// The main archive header.
    Main(Main),
    /// A file or service header.
    File(FileHdr),
    /// The end-of-archive record.
    End(EndHdr),
    /// The RAR 5 archive encryption header (type 4).
    Encryption,
    /// A block type no variant names, skipped by its own size.
    Other,
}

/// The main archive header, both families.
#[derive(Debug, Clone, Default)]
pub(crate) struct Main {
    /// The archive flags word as stored.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub flags: u64,
    /// This file is one volume of a set.
    pub is_volume: bool,
    /// The volume number, zero-based, when the format records it.
    pub volume_number: Option<u32>,
    /// The archive is solid.
    pub solid: bool,
    /// The archive is locked.
    pub locked: bool,
    /// The archive carries a recovery record.
    pub recovery: bool,
    /// Every block after this one is encrypted (RAR 4 flag 0x0080).
    pub headers_encrypted: bool,
    /// The locator extra record (RAR 5 only).
    pub locator: Option<Locator>,
    /// An embedded old-style comment (RAR 4 and RAR 1.3).
    pub comment: Option<CommentSpan>,
}

/// The RAR 5 locator (spec F 3.2.8). Both offsets are stored relative to
/// the first byte of the main header as stored (the first byte after the
/// signature, or behind header encryption the first byte of the IV in
/// front of the main header) and are converted to source coordinates on
/// the way in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Locator {
    /// The locator's flags word as stored.
    pub flags: u64,
    /// The quick open offset exactly as stored, when its flag is set.
    pub raw_quick_open: Option<u64>,
    /// The recovery offset exactly as stored, when its flag is set.
    pub raw_recovery: Option<u64>,
    /// Where the quick open record claims to be, in source coordinates;
    /// `None` for the zero that rar 7.23 writes on every archive it writes,
    /// including ones with no QO record at all.
    pub quick_open: Option<u64>,
    /// Where the recovery record claims to be, in source coordinates.
    pub recovery: Option<u64>,
}

/// A comment's packed bytes and what they declare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommentSpan {
    /// The packed bytes, in source coordinates.
    pub data: Range<u64>,
    /// The declared unpacked size.
    pub unpacked: u64,
    /// The unpack version, 0 when the container does not record one.
    pub version: u8,
    /// The method byte, in the container's own spelling.
    pub method: u8,
    /// What the packed bytes need to become the comment.
    ///
    /// Normalised by the parser that read the block, because the
    /// containers spell "stored" differently and a reader that compares
    /// one container's byte against another's number gets a wrong answer
    /// quietly: the RAR 1.5 to 4.x comment block and sub block spell it
    /// 0x30 (spec F 3.3.9), RAR 5's compression info spells it 0, and
    /// RAR 1.3 records no method byte at all.
    pub codec: CommentCodec,
}

/// What a comment's packed bytes need before they are text (spec F 3.2.9,
/// 3.3.9 and 3.4.5).
///
/// A comment is a stream like a member's, and `rar -z` compresses it: on
/// the genuine legacy corpus the RAR 1.55, RAR 2.50 and RAR 5.50 archives
/// written with `-z` all carry a comment at a LEVEL (method 0x33 or 0x34),
/// and not one of them is stored. A reader that only handles the stored
/// case reports no comment where reference `unrar l` prints one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommentCodec {
    /// The packed bytes ARE the comment.
    Stored,
    /// Spec A's RAR 1.5 algorithm.
    Rar15,
    /// Spec H3 part A's RAR 2.0 algorithm.
    Rar20,
    /// Spec H1's RAR 2.9 algorithm.
    Rar29,
    /// Spec H2's RAR 5 algorithm, with the version the header declares.
    Rar5(u8),
    /// An algorithm this package cannot reach from here, which is no
    /// comment and never an error (spec F question 5).
    Missing,
}

/// Which service record a header is, from its name (spec F 3.2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceName {
    /// The archive comment.
    Comment,
    /// The quick open record.
    QuickOpen,
    /// The recovery record.
    Recovery,
    /// A name this package reports and does nothing else with.
    Other,
}

impl ServiceName {
    /// The service record `name` announces.
    pub(crate) fn from_name(name: &[u8]) -> ServiceName {
        match name {
            b"CMT" => ServiceName::Comment,
            b"QO" => ServiceName::QuickOpen,
            b"RR" => ServiceName::Recovery,
            _ => ServiceName::Other,
        }
    }

    /// How the public API names it.
    pub(crate) fn kind(self) -> ServiceKind {
        match self {
            ServiceName::Comment => ServiceKind::Comment,
            ServiceName::Recovery => ServiceKind::RecoveryRecord,
            _ => ServiceKind::Other,
        }
    }
}

/// A file or service header, both families.
#[derive(Clone)]
pub(crate) struct FileHdr {
    /// The decoded name, as a span of the reader's name arena.
    pub name: NameSpan,
    /// The name exactly as stored, as a span of the header's own bytes.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub raw_name: Range<u32>,
    /// The file flags word, as stored. RAR 1.5 to 4.x and RAR 1.3 keep
    /// their file flags in the block flags, so the two agree there.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub file_flags: u64,
    /// The dictionary-size bits, as stored (RAR 1.5 to 4.x). For RAR 5,
    /// the power alone: bits 10 to 13 at version 0 and 10 to 14 at
    /// version 1, whose fraction only [`FileHdr::dictionary`] carries
    /// (spec F 3.2.6.3).
    pub dict_bits: u16,
    /// The host operating system byte, as stored: the two families number
    /// them differently.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub host_raw: u8,
    /// The stored content checksum word, whatever the container calls it.
    pub raw_checksum: u32,
    /// `Some` when this is a service record and not a member.
    pub service: Option<ServiceName>,
    /// Whether the member is a directory (spec F 3.3.6 for the two-arm
    /// legacy rule).
    pub is_directory: bool,
    /// The unpacked size; `None` when the format says it is unknown.
    pub unpacked_size: Option<u64>,
    /// The packed bytes in THIS volume.
    pub packed_size: u64,
    /// The member continues from the previous volume.
    pub split_before: bool,
    /// The member continues into the next volume.
    pub split_after: bool,
    /// Whether the packed bytes are enciphered.
    pub encrypted: bool,
    /// The member continues the solid chain.
    pub solid: bool,
    /// The modification time, whatever carried it. On a RAR 5 header that
    /// is the extra TIME record's when the record has one and the header
    /// field's otherwise, which is the precedence reference unrar 7.23
    /// follows (spec F 3.2.6.1).
    pub mtime: Option<Timestamp>,
    /// The modification time the HEADER'S OWN field carried, so the block
    /// walk of 5.2 can print that field as the bytes hold it rather than
    /// as `mtime` resolved it. The same as `mtime` in every container that
    /// has only one place to keep a time.
    // Read by `read/dump.rs` alone, which is `#[cfg(test)]`: the block dump
    // of spec F 5.2, checked against `vectors-F/expected/`.
    #[allow(dead_code)]
    pub header_mtime: Option<Timestamp>,
    /// Attributes as stored; how they read depends on `host_os`.
    pub attributes: u32,
    /// Which operating system wrote the member, which is what decides how
    /// to read `attributes`.
    pub host_os: HostOs,
    /// The content checksum as stored. On a leading fragment of a split
    /// member this is the CRC32 of that fragment's PACKED bytes
    /// (spec F 3.5.6).
    pub checksum: Option<Checksum>,
    /// Stored or compressed, with the dictionary size in bytes.
    pub method: Method,
    /// The dictionary size the header declares, whatever the method, and
    /// `None` where the member names none (a directory in every
    /// generation; spec F 3.3.6's bit value 7 is the format's own way of
    /// saying it). Read from the same field as [`Method::Compressed`]'s,
    /// so the two cannot disagree.
    pub dictionary: Option<u64>,
    /// The method code as stored, for [`Unsupported::Method`].
    ///
    /// [`Unsupported::Method`]: crate::Unsupported::Method
    pub method_code: u32,
    /// The unpack version, which selects the decoder (spec F 3.3.5). RAR 5
    /// stores a compression version here instead.
    pub unpack_version: u32,
    /// The RAR 4 family encryption salt (file flag 0x0400).
    pub rar4_salt: Option<[u8; 8]>,
    /// The RAR 5 file encryption record (spec K 3.7.2).
    /// NOT boxed, and the reason is a guard rather than a preference.
    /// The record is 56 bytes of this header's 296 and is `None` on
    /// every member of every unencrypted archive, so a pointer here
    /// shrinks every per-member move of a header. It was tried on 22
    /// Sep 2026 and REFUTED at once by
    /// `tests/allocations.rs::extracting_encrypted_members_allocates_nothing_per_member`,
    /// which read 1.003 allocations a member: an encrypted member pays
    /// a key schedule already, but API promise 2.4 is that extraction
    /// allocates nothing PER MEMBER, and one allocation is one too
    /// many. Shrinking this field wants a smaller record or a slot the
    /// operation owns, not a box.
    pub crypt: Option<crate::crypto::Rar5Record>,
    /// An embedded old-style file comment (spec F 3.3.9). Parsed because
    /// the header checksum rule turns on where the embedded block starts;
    /// the API surfaces the ARCHIVE comment only, so nothing reads it.
    #[allow(dead_code)]
    pub comment: Option<CommentSpan>,
    /// The recovery percentage an `RR` service record's own extra record
    /// declares (spec F 3.2.9); `None` on every other header.
    ///
    /// A stated 0 is no percentage: the reference stores 1 to 1,000 (spec
    /// L 3.5.1), and the non-zero form keeps this header inside its size
    /// gate (`read::extract::tests::no_member_header_travels_by_value`).
    pub recovery_percent: Option<std::num::NonZeroU32>,
    /// `Some` when the member is a redirection: RAR 5's extra record of
    /// type 5, or the RAR 4 family's link mode (spec F 3.2.6.2, 3.3.12).
    pub redirect: Option<Redirect>,
    /// Whether the member is an older version of a file (spec F 3.2.6.4,
    /// 3.3.6): 0 for a file that is not one, RAR 5's version number (1 or
    /// more, from its extra record of type 4), or [`VERSION_IN_NAME`] for
    /// the older container's file flag 0x0800. One word, because this
    /// header travels per member and its size is gated
    /// (`read::extract::tests::no_member_header_travels_by_value`);
    /// [`FileHdr::file_version`] reads it.
    pub version: u32,
}

/// The bit of [`FileHdr::dict_bits`] that marks a header as unsound. The
/// field's own values are below 32, and the header's size is gated
/// (`read::extract::tests::no_member_header_travels_by_value`), so the
/// mark rides a bit the field never uses and costs the header no byte.
const UNSOUND: u16 = 0x8000;

/// [`FileHdr::version`] for a member the older container flags as a
/// version without stating a number.
pub(crate) const VERSION_IN_NAME: u32 = u32::MAX;

/// The largest RAR 4 family link target the engine reads (spec F 3.3.12).
pub(crate) const RAR4_LINK_MAX: u64 = 64 * 1024;

/// A redirection member's record, as the header parsers leave it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Redirect {
    /// The record's type field as stored: 1 for the RAR 4 family's link.
    /// The raw code, not a [`RedirectionKind`](crate::read::RedirectionKind),
    /// because `FileHdr` travels per member and the enum is twice the size
    /// (`read::extract::tests::no_member_header_travels_by_value`).
    pub code: u64,
    /// RAR 5's directory flag (0x0001).
    pub dir: bool,
    /// Where the target's bytes are: in the HEADER's bytes as a parser
    /// leaves it, and in the reader's name arena once the reader has
    /// copied them there. Empty for the RAR 4 family, whose target is the
    /// member's content.
    pub target_start: u32,
    /// The target's length, in bytes.
    pub target_len: u32,
    /// The record cannot be used (spec F 3.8.1): extraction reports the
    /// member as `Corrupt(Redirection)`. A listing still shows it.
    pub fault: bool,
    /// The RAR 4 family's form: the target is the member's decoded
    /// content, not a field of the header.
    pub in_content: bool,
}

impl Redirect {
    /// Which kind the record names.
    pub(crate) fn kind(&self) -> crate::read::RedirectionKind {
        crate::read::RedirectionKind::from_rar5(self.code)
    }

    /// The target's span, in whatever the current coordinates are.
    pub(crate) fn target(&self) -> std::ops::Range<usize> {
        self.target_start as usize..self.target_start as usize + self.target_len as usize
    }
}

impl FileHdr {
    /// Whether this header was read although its own checksum failed, or
    /// is the quick open copy read in place of one that did
    /// (`ReadOptions::read_damaged`). A member under it is good only by
    /// its own data checksum: with none, it fails (spec F 4.6 rule 4).
    pub(crate) fn unsound(&self) -> bool {
        self.dict_bits & UNSOUND != 0
    }

    /// Mark the header unsound. The walk does it after the parse, where
    /// the checksum is judged; a parser clears it by writing the field.
    pub(crate) fn mark_unsound(&mut self) {
        self.dict_bits |= UNSOUND;
    }

    /// A header that names nothing, for a caller that owns the slot a
    /// parser fills.
    ///
    /// `FileHdr` is 296 bytes and costs that much every time it is moved.
    /// Building one inside the parser and handing it back compiled to a
    /// chain of `memcpy` calls of 0x128 and 0x138 bytes per member, read
    /// off the release disassembly on 22 Sep 2026 on a path that runs once
    /// per member; a caller-owned slot is how those go away.
    /// Every field here is a placeholder: a
    /// parser that fills this slot overwrites all of them, which the
    /// exhaustive destructuring in `rar5::parse_file_into` and
    /// `rar4::parse_file_into` is what makes the compiler check.
    pub(crate) fn empty() -> FileHdr {
        FileHdr {
            name: 0..0,
            raw_name: 0..0,
            file_flags: 0,
            dict_bits: 0,
            host_raw: 0,
            raw_checksum: 0,
            service: None,
            is_directory: false,
            unpacked_size: None,
            packed_size: 0,
            split_before: false,
            split_after: false,
            encrypted: false,
            solid: false,
            mtime: None,
            header_mtime: None,
            attributes: 0,
            host_os: HostOs::Windows,
            checksum: None,
            method: Method::Stored,
            dictionary: None,
            method_code: 0,
            unpack_version: 0,
            rar4_salt: None,
            crypt: None,
            comment: None,
            recovery_percent: None,
            redirect: None,
            version: 0,
        }
    }

    /// Which older version of a file this member is, if it is one.
    pub(crate) fn file_version(&self) -> Option<crate::read::FileVersion> {
        match self.version {
            0 => None,
            VERSION_IN_NAME => Some(crate::read::FileVersion::InName),
            number => Some(crate::read::FileVersion::Numbered(number)),
        }
    }
}

/// The end-of-archive record, both families.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EndHdr {
    /// The end flags word as stored.
    pub flags: u64,
    /// Another volume follows.
    pub next_follows: bool,
    /// The volume number, when the RAR 4 record carries one.
    pub volume_number: Option<u32>,
    /// The archive data CRC32, when the RAR 4 record carries one.
    pub archive_crc32: Option<u32>,
}

impl Fields {
    /// The public block kind for these fields.
    pub(crate) fn kind(&self) -> BlockKind {
        match self {
            Fields::Marker => BlockKind::Other(0x72),
            Fields::Main(_) => BlockKind::Main,
            Fields::File(f) => match f.service {
                Some(name) => BlockKind::Service(name.kind()),
                None => BlockKind::File,
            },
            Fields::End(_) => BlockKind::End,
            Fields::Encryption => BlockKind::Other(4),
            Fields::Other => BlockKind::Other(0),
        }
    }
}
