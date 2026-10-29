//! Format constants the two writers need that the carried layer does not
//! already name (spec G sections 3.2, 3.3 and 3.14.1 to 3.14.6).
//!
//! Nothing here is a decision: every value is a number the format fixes,
//! kept in one small file so that a reader of this package can check the
//! catalogue against the specification in one pass.

/// RAR 5 block type: the archive encryption header (spec G 3.3.6).
pub(crate) const BLOCK_TYPE_ARCHIVE_ENCRYPTION: u64 = 4;

/// RAR 5 block flag: this block depends on the file block before it.
// Never written: no block this package writes depends on the one
// before it (spec G 3.2). The catalogue names the bit anyway.
#[allow(dead_code)]
pub(crate) const BLOCK_DEPENDS_ON_PREVIOUS: u64 = 0x0020;

/// RAR 5 archive flag: the members are one solid group.
pub(crate) const ARCHIVE_IS_SOLID: u64 = 0x0004;
/// RAR 5 archive flag: the archive is locked.
pub(crate) const ARCHIVE_IS_LOCKED: u64 = 0x0010;

/// RAR 5 file flag: the unpacked size is unknown. Never written here
/// (spec G 3.3.3), and named so that the bit is accounted for.
// The catalogue names the bit although nothing sets it.
#[allow(dead_code)]
pub(crate) const FILE_UNKNOWN_UNPACKED_SIZE: u64 = 0x0008;

/// RAR 5 extra record type: the member's encryption parameters (spec K 3.5).
pub(crate) const FILE_EXTRA_ENCRYPTION: u64 = 0x01;
/// RAR 5 extra record type: a service block's own parameter.
pub(crate) const FILE_EXTRA_SERVICE_DATA: u64 = 0x07;

/// RAR 5 compression information: bits of the algorithm version.
pub(crate) const COMPRESSION_VERSION_BITS: u32 = 0;
/// RAR 5 compression information: the solid continuation bit.
pub(crate) const COMPRESSION_SOLID_BIT: u64 = 1 << 6;
/// RAR 5 compression information: the first bit of the method field.
pub(crate) const COMPRESSION_METHOD_SHIFT: u32 = 7;
/// RAR 5 compression information: the first bit of the dictionary power.
pub(crate) const COMPRESSION_DICTIONARY_SHIFT: u32 = 10;

/// The dictionary power the RAR 5 field can say: 128 KiB << 0 to 128 KiB << 15.
pub(crate) const MAX_DICTIONARY_POWER: u32 = 15;

/// The service names spec G 3.3.4 and 3.14.8 place.
pub(crate) const SERVICE_COMMENT: &[u8] = b"CMT";
/// The quick-open index service name.
pub(crate) const SERVICE_QUICK_OPEN: &[u8] = b"QO";
/// The inline recovery record service name.
pub(crate) const SERVICE_RECOVERY: &[u8] = b"RR";

// ---- The RAR 4 family (spec G 3.14) -------------------------------------

/// The marker block every RAR 4 family archive opens with.
pub(crate) const RAR4_MARKER: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];

/// RAR 4 block type: the main header.
pub(crate) const R4_TYPE_MAIN: u8 = 0x73;
/// RAR 4 block type: a file header.
pub(crate) const R4_TYPE_FILE: u8 = 0x74;
/// RAR 4 block type: a sub block.
pub(crate) const R4_TYPE_SUB: u8 = 0x7a;
/// RAR 4 block type: the end block.
pub(crate) const R4_TYPE_END: u8 = 0x7b;

/// RAR 4 header flag: a data area follows this header.
pub(crate) const R4_HAS_DATA: u16 = 0x8000;
/// RAR 4 header flag: a reader that does not know this block may skip it.
pub(crate) const R4_REWRITER_MAY_OMIT: u16 = 0x4000;

/// RAR 4 main flag: this file is one volume of a set.
pub(crate) const R4_MAIN_VOLUME: u16 = 0x0001;
/// RAR 4 main flag: an old-style archive comment follows the header.
// Never written: a comment goes in a sub block (spec G 3.14.8).
#[allow(dead_code)]
pub(crate) const R4_MAIN_COMMENT: u16 = 0x0002;
/// RAR 4 main flag: the archive is locked.
pub(crate) const R4_MAIN_LOCKED: u16 = 0x0004;
/// RAR 4 main flag: the members are one solid group.
pub(crate) const R4_MAIN_SOLID: u16 = 0x0008;
/// RAR 4 main flag: the volumes are named in the numbered form.
pub(crate) const R4_MAIN_NUMBERED_VOLUMES: u16 = 0x0010;
/// RAR 4 main flag: an authenticity block is present. Never written.
// The catalogue names the bit although nothing sets it.
#[allow(dead_code)]
pub(crate) const R4_MAIN_AUTHENTICITY: u16 = 0x0020;
/// RAR 4 main flag: this volume carries a recovery record.
pub(crate) const R4_MAIN_RECOVERY: u16 = 0x0040;
/// RAR 4 main flag: the block headers are encrypted.
pub(crate) const R4_MAIN_ENCRYPTED_HEADERS: u16 = 0x0080;
/// RAR 4 main flag: this is the first volume of a set.
pub(crate) const R4_MAIN_FIRST_VOLUME: u16 = 0x0100;

/// RAR 4 file flag: this fragment continues a member from the previous volume.
pub(crate) const R4_FILE_CONTINUED_FROM_PREVIOUS: u16 = 0x0001;
/// RAR 4 file flag: this fragment continues into the next volume.
pub(crate) const R4_FILE_CONTINUES_IN_NEXT: u16 = 0x0002;
/// RAR 4 file flag: the member data is encrypted.
pub(crate) const R4_FILE_ENCRYPTED: u16 = 0x0004;
/// RAR 4 file flag: this member continues the previous member's history.
pub(crate) const R4_FILE_SOLID: u16 = 0x0010;
/// RAR 4 file flag: the dictionary field, bits 5 to 7.
pub(crate) const R4_FILE_DICTIONARY_MASK: u16 = 0x00e0;
/// The shift that puts a dictionary value into [`R4_FILE_DICTIONARY_MASK`].
pub(crate) const R4_FILE_DICTIONARY_SHIFT: u32 = 5;
/// The dictionary field value that marks a directory entry instead.
pub(crate) const R4_FILE_DICTIONARY_IS_DIRECTORY: u16 = 7;
/// RAR 4 file flag: the two high size fields are present.
pub(crate) const R4_FILE_HIGH_SIZES: u16 = 0x0100;
/// RAR 4 file flag: the name carries the two-part encoded form. Never written.
// Never written: names go out in the plain form (spec G 3.14.5).
#[allow(dead_code)]
pub(crate) const R4_FILE_ENCODED_NAME: u16 = 0x0200;
/// RAR 4 file flag: a salt is present.
pub(crate) const R4_FILE_SALT: u16 = 0x0400;
/// RAR 4 file flag: an extended time field is present.
pub(crate) const R4_FILE_EXTENDED_TIME: u16 = 0x1000;

/// RAR 4 end flag: another volume follows.
pub(crate) const R4_END_NOT_LAST_VOLUME: u16 = 0x0001;
/// RAR 4 end flag: a 4 byte checksum of the volume set follows.
// Never written: no volume-set checksum (spec G 3.14.6).
#[allow(dead_code)]
pub(crate) const R4_END_HAS_SET_CHECKSUM: u16 = 0x0002;
/// RAR 4 end flag: seven reserved bytes for a recovery volume follow.
pub(crate) const R4_END_HAS_REV_SPACE: u16 = 0x0004;
/// RAR 4 end flag: this volume's own zero-based number follows.
pub(crate) const R4_END_HAS_VOLUME_NUMBER: u16 = 0x0008;

/// The RAR 4 method byte of a stored member; levels 1 to 5 follow it.
pub(crate) const R4_METHOD_STORED: u8 = 0x30;
/// The RAR 4 version byte of a stored member.
pub(crate) const R4_VERSION_STORED: u8 = 20;
/// The RAR 4 version byte of a compressed or encrypted member.
pub(crate) const R4_VERSION_COMPRESSED: u8 = 29;

/// The largest name a RAR 4 header can say, its length field being 16 bits.
pub(crate) const R4_MAX_NAME: usize = u16::MAX as usize;
/// The largest volume count a RAR 4 end block can number.
pub(crate) const R4_MAX_VOLUMES: u32 = u16::MAX as u32;
/// What a RAR 4 size field holds before the high fields are needed.
pub(crate) const R4_SIZE_FIELD_LIMIT: u64 = 1 << 32;

/// The file type field of a Unix mode, as a member's attribute word
/// carries it under a Unix host.
pub(crate) const UNIX_TYPE_BITS: u32 = 0o170000;
/// The symbolic link's value of [`UNIX_TYPE_BITS`]: what makes a RAR 4
/// family member a link to every reader (spec F 3.3.12).
pub(crate) const UNIX_TYPE_SYMLINK: u32 = 0o120000;
