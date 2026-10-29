//! The RAR 4 family block emitters (spec G section 3.14).
//!
//! One emitter serves RAR 2.9, 3.0 and 4.0: they differ in the version
//! byte a file header carries and in which features the writer permits,
//! not in any code path here (spec G question 7).

use crate::checksum::crc32;
use crate::read::dostime;
use crate::types::Timestamp;
use crate::write::consts::*;
use crate::write::rar5::Fragment;
use crate::write::Digest;

/// Frames a RAR 4 block: the 16 bit checksum of everything from the type
/// byte on, the type, the flags, the header's own length, and, when the
/// flags say so, the length of the data that follows (spec G 3.14.1).
pub(crate) fn frame(kind: u8, flags: u16, data_size: Option<u32>, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 14);
    frame_into(&mut out, kind, flags, data_size, body);
    out
}

/// The most a file header holds beside the member's name: the frame's 7
/// bytes, the 4 byte data size, the 21 bytes of fixed fields, the 8 bytes
/// of high size fields, an 8 byte salt and an extended time area of 5.
pub(crate) const FILE_HEADER_REST_MOST: usize = 7 + 4 + 21 + 8 + 8 + 5;

/// The longest name a file header can carry and still state its own
/// length, which is a 16 bit field over the WHOLE header (spec G section
/// 4: if the run returns Ok, every header's size fields agree). The name
/// length field alone would admit 65,535.
pub(crate) const MAX_NAME: usize = R4_MAX_NAME - FILE_HEADER_REST_MOST;

/// [`frame`] into a caller's buffer, which is REPLACED by the framed
/// block and never allocated here once it has grown (spec G 7.3).
///
/// The checksum covers everything from the type byte on, so the block is
/// laid down with two placeholder bytes in front of it and both the
/// length and the checksum are filled in once the body is there. One
/// buffer does the work the two of [`frame`] used to.
pub(crate) fn frame_into(
    out: &mut Vec<u8>,
    kind: u8,
    flags: u16,
    data_size: Option<u32>,
    body: &[u8],
) {
    out.clear();
    out.extend_from_slice(&[0, 0]); // the checksum, filled in below
    out.push(kind);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&[0, 0]); // the size field, filled in below
    if let Some(size) = data_size {
        out.extend_from_slice(&size.to_le_bytes());
    }
    out.extend_from_slice(body);

    // The header's declared length counts its own checksum, which is
    // exactly the two bytes in front of it: the whole buffer's length.
    // The field is 16 bits, and a header past it would be written with
    // the length cut short over a checksum of the whole: an archive that
    // does not open, from a run that returned Ok. The one field a caller
    // can make that long is a member's name, which `MAX_NAME` bounds
    // where the name is taken, so nothing reaches here that long.
    debug_assert!(out.len() <= usize::from(u16::MAX));
    let size = out.len() as u16;
    out[5..7].copy_from_slice(&size.to_le_bytes());
    let checksum = crc32(&out[2..]) as u16;
    out[..2].copy_from_slice(&checksum.to_le_bytes());
}

/// What the main header says (spec G 3.14.2).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MainPlan {
    /// This file is one volume of a set.
    pub(crate) volume_set: bool,
    /// This is the first volume of the set.
    pub(crate) first_volume: bool,
    /// The volumes are named in the numbered form.
    pub(crate) numbered_volumes: bool,
    /// The archive is locked.
    pub(crate) locked: bool,
    /// The members are one solid group.
    pub(crate) solid: bool,
    /// This volume carries an inline recovery record.
    pub(crate) recovery: bool,
    /// The block headers are encrypted.
    pub(crate) encrypted_headers: bool,
}

/// The main header. Its two reserved fields are zero in everything this
/// crate writes and in everything genuine `rar` 4.20 writes.
pub(crate) fn main_header(plan: &MainPlan) -> Vec<u8> {
    let mut flags = 0u16;
    if plan.volume_set {
        flags |= R4_MAIN_VOLUME;
    }
    if plan.locked {
        flags |= R4_MAIN_LOCKED;
    }
    if plan.solid {
        flags |= R4_MAIN_SOLID;
    }
    if plan.volume_set && plan.numbered_volumes {
        flags |= R4_MAIN_NUMBERED_VOLUMES;
    }
    if plan.recovery {
        flags |= R4_MAIN_RECOVERY;
    }
    if plan.encrypted_headers {
        flags |= R4_MAIN_ENCRYPTED_HEADERS;
    }
    if plan.volume_set && plan.first_volume {
        flags |= R4_MAIN_FIRST_VOLUME;
    }
    frame(R4_TYPE_MAIN, flags, None, &[0, 0, 0, 0, 0, 0])
}

/// What one file header or sub block says (spec G 3.14.3).
pub(crate) struct FilePlan<'a> {
    /// The name as stored, `\` separated, raw UTF-8 (spec G 3.14.5).
    pub(crate) name: &'a [u8],
    /// The whole member's size, on every fragment.
    pub(crate) unpacked_size: u64,
    /// This fragment's stored length, which is also the block's data size.
    pub(crate) packed_size: u64,
    /// The host byte: 0 MS-DOS, 1 OS/2, 2 Windows, 3 Unix.
    pub(crate) host_os: u8,
    /// The payload's checksum. Only a CRC32 can be said here.
    pub(crate) crc32: u32,
    /// The modification time, or none.
    pub(crate) mtime: Option<Timestamp>,
    /// 0 stored, 1 to 5 the levels of the same number.
    pub(crate) method: u8,
    /// The attribute word, uninterpreted.
    pub(crate) attributes: u32,
    /// Whether this entry is a directory.
    pub(crate) is_directory: bool,
    /// The dictionary field's value, 0 to 6.
    pub(crate) dictionary: u16,
    /// This member continues the previous member's history.
    pub(crate) solid: bool,
    /// Where this fragment sits.
    pub(crate) fragment: Fragment,
    /// The member's encryption salt (spec K), or none.
    pub(crate) salt: Option<[u8; 8]>,
    /// Whether this is a sub block rather than a file header.
    pub(crate) sub_block: bool,
    /// Whether a reader that does not know this block may skip it.
    pub(crate) skip_if_unknown: bool,
    /// A sub block's own fields, which follow the name (spec G 3.14.8);
    /// empty on a file header and on the comment.
    pub(crate) after_name: &'a [u8],
}

/// A file header, or a sub block, which is the same layout under a
/// different block type.
pub(crate) fn file_header(plan: &FilePlan<'_>) -> Vec<u8> {
    let mut scratch = crate::write::rar5::Scratch::default();
    let mut out = Vec::with_capacity(plan.name.len() + 48);
    file_header_into(plan, &mut scratch, &mut out);
    out
}

/// The same, through a caller's reused buffers: `scratch.specific` is
/// the body and `out` is REPLACED by the header image (spec G 7.3).
pub(crate) fn file_header_into(
    plan: &FilePlan<'_>,
    scratch: &mut crate::write::rar5::Scratch,
    out: &mut Vec<u8>,
) {
    let mut flags = R4_HAS_DATA;
    if plan.skip_if_unknown {
        flags |= R4_REWRITER_MAY_OMIT;
    }
    if plan.fragment.continued() {
        flags |= R4_FILE_CONTINUED_FROM_PREVIOUS;
    }
    if plan.fragment.continues() {
        flags |= R4_FILE_CONTINUES_IN_NEXT;
    }
    if plan.salt.is_some() {
        flags |= R4_FILE_ENCRYPTED | R4_FILE_SALT;
    }
    if plan.solid {
        flags |= R4_FILE_SOLID;
    }
    // The dictionary bits carry a directory instead of a size, which is
    // why a directory has no dictionary and never needs one.
    let dictionary = if plan.is_directory {
        R4_FILE_DICTIONARY_IS_DIRECTORY
    } else {
        plan.dictionary.min(6)
    };
    flags |= (dictionary << R4_FILE_DICTIONARY_SHIFT) & R4_FILE_DICTIONARY_MASK;

    let high_sizes =
        plan.packed_size >= R4_SIZE_FIELD_LIMIT || plan.unpacked_size >= R4_SIZE_FIELD_LIMIT;
    if high_sizes {
        flags |= R4_FILE_HIGH_SIZES;
    }

    // A time the field cannot say is written as the nearest it can (spec
    // G section 4), settled once so the field and the extended time agree.
    let mtime = plan.mtime.map(nearest_stated);
    let extended = mtime.and_then(extended_time);
    if extended.is_some() {
        flags |= R4_FILE_EXTENDED_TIME;
    }

    let body = &mut scratch.specific;
    body.clear();
    body.extend_from_slice(&(plan.unpacked_size as u32).to_le_bytes());
    body.push(plan.host_os);
    body.extend_from_slice(&plan.crc32.to_le_bytes());
    body.extend_from_slice(&to_dos(mtime).to_le_bytes());
    body.push(
        if plan.method == 0 && plan.salt.is_none() && !plan.sub_block {
            R4_VERSION_STORED
        } else {
            R4_VERSION_COMPRESSED
        },
    );
    body.push(R4_METHOD_STORED + plan.method);
    body.extend_from_slice(&(plan.name.len() as u16).to_le_bytes());
    body.extend_from_slice(&plan.attributes.to_le_bytes());
    if high_sizes {
        body.extend_from_slice(&((plan.packed_size >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&((plan.unpacked_size >> 32) as u32).to_le_bytes());
    }
    body.extend_from_slice(plan.name);
    body.extend_from_slice(plan.after_name);
    if let Some(salt) = plan.salt {
        body.extend_from_slice(&salt);
    }
    if let Some(area) = extended {
        body.extend_from_slice(&area[..extended_time_len(&area)]);
    }

    let kind = if plan.sub_block {
        R4_TYPE_SUB
    } else {
        R4_TYPE_FILE
    };
    frame_into(out, kind, flags, Some(plan.packed_size as u32), body);
}

/// The comment's sub block (spec G 3.14.8): stored, its checksum field
/// the whole CRC32 of the comment's bytes, nothing after the name.
pub(crate) fn comment_sub_block(comment: &[u8], host_os: u8) -> Vec<u8> {
    sub_block(SERVICE_COMMENT, comment, host_os, false, &[])
}

/// The recovery record's sub block (spec G 3.14.8, SPEC-L 3.7): after
/// the name `Protect+`, then the count of parity sectors and the count of
/// protected sectors, 4 bytes each, and 4 zero bytes; a block a reader
/// that does not know it may skip.
pub(crate) fn recovery_sub_block(
    record: &[u8],
    host_os: u8,
    counts: &crate::recovery::legacy::LegacyRecord,
) -> Vec<u8> {
    let mut fields = [0u8; 20];
    fields[..8].copy_from_slice(b"Protect+");
    fields[8..12].copy_from_slice(&(counts.parity as u32).to_le_bytes());
    fields[12..16].copy_from_slice(&(counts.sectors as u32).to_le_bytes());
    sub_block(SERVICE_RECOVERY, record, host_os, true, &fields)
}

/// A sub block: a file header's layout under another type, over a stored
/// data area that carries its own CRC32.
fn sub_block(
    name: &[u8],
    data: &[u8],
    host_os: u8,
    skip_if_unknown: bool,
    after_name: &[u8],
) -> Vec<u8> {
    let plan = FilePlan {
        name,
        unpacked_size: data.len() as u64,
        packed_size: data.len() as u64,
        host_os,
        crc32: crc32(data),
        mtime: None,
        method: 0,
        attributes: 0,
        is_directory: false,
        dictionary: 0,
        solid: false,
        fragment: Fragment::Whole,
        salt: None,
        sub_block: true,
        skip_if_unknown,
        after_name,
    };
    file_header(&plan)
}

/// What the end block says (spec G 3.14.6).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EndPlan {
    /// This archive is one volume of a set.
    pub(crate) volume_set: bool,
    /// Another volume follows this one.
    pub(crate) next_volume: bool,
    /// This volume's zero-based number.
    pub(crate) volume_number: u16,
}

/// The end block.
///
/// This crate does not write the 4 byte set checksum the reference puts
/// behind flag 0x0002: the specification names the field and not the
/// value, and a flag whose field is absent is what the flag is FOR. The
/// seven reserved bytes behind flag 0x0004 are written, as the reference
/// writes them, so that a recovery volume has the room it expects.
pub(crate) fn end_block(plan: &EndPlan) -> Vec<u8> {
    let mut flags = R4_REWRITER_MAY_OMIT;
    let mut body = Vec::new();
    if plan.volume_set {
        if plan.next_volume {
            flags |= R4_END_NOT_LAST_VOLUME;
        }
        flags |= R4_END_HAS_VOLUME_NUMBER | R4_END_HAS_REV_SPACE;
        body.extend_from_slice(&plan.volume_number.to_le_bytes());
        body.extend_from_slice(&[0u8; 7]);
    }
    frame(R4_TYPE_END, flags, None, &body)
}

/// The first second the header's time field can say: 1980-01-01 00:00:00,
/// the field's year 0 (spec G 3.14.4).
const FIRST_STATED_SECOND: i64 = 315_532_800;
/// The last: 2107-12-31 23:59:59, the field's year 127 at its last even
/// second with the extended time's one second bit.
const LAST_STATED_SECOND: i64 = 4_354_819_199;
/// The largest fraction of a second the extended time holds, in
/// nanoseconds: 9,999,999 units of 100 ns.
const LAST_STATED_NANOS: u32 = 999_999_900;

/// `time`, or the nearest time a file header can state when `time` is
/// outside 1980 to 2107 (spec G section 4): the first instant of 1980
/// for an earlier one, and the last 100 ns of 2107 for a later one.
pub(crate) fn nearest_stated(time: Timestamp) -> Timestamp {
    if time.unix_seconds < FIRST_STATED_SECOND {
        return Timestamp {
            unix_seconds: FIRST_STATED_SECOND,
            nanos: 0,
        };
    }
    if time.unix_seconds > LAST_STATED_SECOND {
        return Timestamp {
            unix_seconds: LAST_STATED_SECOND,
            nanos: LAST_STATED_NANOS,
        };
    }
    time
}

/// A modification time as the header's packed DOS word (spec G 3.14.4):
/// the year less 1980, month, day, hour, minute and the second halved.
/// `time` is one the field can say ([`nearest_stated`]).
pub(crate) fn to_dos(time: Option<Timestamp>) -> u32 {
    let Some(time) = time else {
        return 0;
    };
    let (year, month, day, hour, minute, second) = dostime::civil(time.unix_seconds);
    debug_assert!((1980..=2107).contains(&year));
    (((year - 1980) as u32) << 25)
        | (month << 21)
        | (day << 16)
        | (hour << 11)
        | (minute << 5)
        | (second / 2)
}

/// The extended time area, when the header's own field cannot say the
/// time alone (spec G 3.14.4): an odd second, or a fraction.
///
/// Only the modification time is written, so only the top group of the
/// word is ever set: bit 3 the time is present, bit 2 one second is added
/// to the field's value, bits 0 and 1 the count of fraction bytes. The
/// fraction is a three byte little endian count of 100 ns units. A count
/// below three would hold its HIGH order bytes; all three are written
/// whenever there is a fraction, so no short form is.
pub(crate) fn extended_time(time: Timestamp) -> Option<[u8; 5]> {
    let odd_second = time.unix_seconds.rem_euclid(2) == 1;
    let units = time.nanos / 100;
    if !odd_second && units == 0 {
        return None;
    }
    let mut word = 0x8000u16;
    if odd_second {
        word |= 0x4000;
    }
    if units != 0 {
        word |= 3 << 12;
    }
    let mut area = [0u8; 5];
    area[..2].copy_from_slice(&word.to_le_bytes());
    area[2..].copy_from_slice(&units.to_le_bytes()[..3]);
    Some(area)
}

/// How many bytes of [`extended_time`]'s area are written.
pub(crate) fn extended_time_len(area: &[u8; 5]) -> usize {
    let flags = u16::from_le_bytes([area[0], area[1]]);
    2 + usize::from((flags >> 12) & 0x3)
}

/// The dictionary value a file header's bits 5 to 7 carry: the fitted
/// dictionary as `64 KiB << value`, clamped to what three bits can say.
pub(crate) fn dictionary_value(dictionary: u64) -> u16 {
    let quantum = 64u64 << 10;
    if dictionary <= quantum {
        return 0;
    }
    ((dictionary / quantum).trailing_zeros() as u16).min(6)
}

/// A digest the RAR 4 family can carry. The family has no hash record, so
/// a BLAKE2sp digest never reaches a header here; `Writer::new` refuses
/// the combination before any output.
pub(crate) fn crc_of(digest: Option<Digest>) -> u32 {
    match digest {
        Some(Digest::Crc32(value)) => value,
        _ => 0,
    }
}
