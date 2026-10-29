//! RAR 1.5, 2.0 and RAR 4 family header fields (spec F 3.3). One container
//! serves every writer from RAR 1.5 to RAR 4.x; what changes between
//! generations is which fields and flags are used.

use std::ops::Range;

use crate::error::{Corruption, Error, ErrorKind, Result};
use crate::read::block::{CommentCodec, CommentSpan, EndHdr, Fields, FileHdr, Main, ServiceName};
use crate::read::dostime;
use crate::types::{Checksum, HostOs, Method};

/// Block types (spec F 3.3.3).
pub(crate) const T_MARKER: u8 = 0x72;
pub(crate) const T_MAIN: u8 = 0x73;
pub(crate) const T_FILE: u8 = 0x74;
pub(crate) const T_COMMENT: u8 = 0x75;
pub(crate) const TYPE_76: u8 = 0x76;
pub(crate) const T_SUB_OLD: u8 = 0x77;
pub(crate) const OLD_RECOVERY_RECORD: u8 = 0x78;
pub(crate) const TYPE_79: u8 = 0x79;
pub(crate) const SERVICE_BLOCK: u8 = 0x7A;
pub(crate) const T_END: u8 = 0x7B;

pub(crate) const DATA_LENGTH_FOLLOWS: u16 = 0x8000;

/// Main header flags (spec F 3.3.4).
pub(crate) const MF_VOLUME: u16 = 0x0001;
pub(crate) const MF_COMMENT: u16 = 0x0002;
pub(crate) const MF_LOCK: u16 = 0x0004;
pub(crate) const MF_SOLID: u16 = 0x0008;
// Named but not acted on: this group is spec F 3.3.4's flag
// table in full.
#[allow(dead_code)]
pub(crate) const MF_NEW_NAMING: u16 = 0x0010;
pub(crate) const MF_RECOVERY: u16 = 0x0040;
pub(crate) const MF_ENC_HEADERS: u16 = 0x0080;
// Named but not acted on: this group is spec F 3.3.4's flag
// table in full.
#[allow(dead_code)]
pub(crate) const MF_FIRST_VOLUME: u16 = 0x0100;

/// File flags (spec F 3.3.6).
pub(crate) const FF_SPLIT_BEFORE: u16 = 0x0001;
pub(crate) const FF_SPLIT_AFTER: u16 = 0x0002;
pub(crate) const FF_ENCRYPTED: u16 = 0x0004;
pub(crate) const FF_COMMENT: u16 = 0x0008;
pub(crate) const FF_SOLID: u16 = 0x0010;
pub(crate) const FF_DICT_MASK: u16 = 0x00E0;
pub(crate) const HIGH_SIZE_HALVES_PRESENT: u16 = 0x0100;
pub(crate) const FF_UNICODE: u16 = 0x0200;
pub(crate) const FF_SALT: u16 = 0x0400;
// Named but not acted on: this group is spec F 3.3.6's flag
// table in full.
#[allow(dead_code)]
pub(crate) const FF_VERSION: u16 = 0x0800;
pub(crate) const FF_EXT_TIME: u16 = 0x1000;

/// The dictionary-bit value RAR 2.0 and every later writer uses to mark a
/// directory.
pub(crate) const DICT_DIRECTORY: u16 = 7;

/// Where the checked span of a comment block standing between blocks
/// ends: its header checksum covers offsets 2 to 12 of the block, so a
/// block shorter than this many bytes cannot fit it (spec F 3.3.3 B2).
pub(crate) const LONE_COMMENT_CHECKED: usize = 13;

/// End-of-archive flags (spec F 3.3.10).
pub(crate) const EF_NEXT_VOLUME: u16 = 0x0001;
pub(crate) const EF_ARCHIVE_CRC: u16 = 0x0002;
// Named but not acted on: this group is spec F 3.3.10's flag
// table in full.
#[allow(dead_code)]
pub(crate) const EF_REV_SPACE: u16 = 0x0004;
pub(crate) const EF_VOL_NUMBER: u16 = 0x0008;

/// The seven bytes every block begins with.
pub(crate) const COMMON: usize = 7;

fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Header))
}

/// The fields every RAR 1.5 to 4.x block begins with.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Common {
    /// The stored header CRC16.
    pub crc: u16,
    /// The block type.
    pub btype: u8,
    /// The header flags.
    pub flags: u16,
    /// The header size, counting from the START of the block, CRC field
    /// included, unlike RAR 5.
    pub size: u16,
    /// The data length that follows the header.
    pub data_size: u64,
}

/// Read the common fields from the first seven bytes of a block.
///
/// **The trap of spec F 3.3.2**: for a FILE (0x74) and a service block (0x7A) the
/// packed size field inside the header is the data length and there is no
/// separate additional-size field, even though flag 0x8000 is set. Taking
/// the four bytes at offset 7 as an additional size on a file block reads
/// the low half of the packed size as the data length and every field after
/// it at the wrong offset, and then walks to a position that is not a
/// block: plausible garbage rather than an outright failure.
pub(crate) fn parse_common(head: &[u8]) -> Result<Common> {
    if head.len() < COMMON {
        return Err(corrupt());
    }
    let crc = u16::from_le_bytes([head[0], head[1]]);
    let btype = head[2];
    let flags = u16::from_le_bytes([head[3], head[4]]);
    let size = u16::from_le_bytes([head[5], head[6]]);
    if usize::from(size) < COMMON {
        return Err(corrupt());
    }
    let has_own_size = btype == T_FILE || btype == SERVICE_BLOCK;
    let data_size = if flags & DATA_LENGTH_FOLLOWS != 0 && !has_own_size {
        u64::from(take_u32(head, 7)?)
    } else {
        0
    };
    Ok(Common {
        crc,
        btype,
        flags,
        size,
        data_size,
    })
}

/// The fixed part of the main header (type 0x73), and of an old-style
/// comment block (type 0x75): both are thirteen bytes.
pub(crate) const MAIN_FIXED: usize = 13;
/// The largest data area an old subblock's checksum is re-checked over.
/// Every such block observed carries a few bytes; the bound is what keeps
/// a declared size from turning one header into a long read.
pub(crate) const SUB_OLD_CHECKSUM_MAX: u64 = 4096;
pub(crate) const COMMENT_FIXED: usize = 13;

/// The header checksum is the low 16 bits of the standard CRC32 over the
/// block from the header type byte to the end of the header
/// ([`checksum_end`] says where that is).
pub(crate) fn header_checksum(head: &[u8], common: &Common) -> u16 {
    let end = checksum_end(head, common);
    crate::checksum::crc32(&head[2..end]) as u16
}

/// Where the checksum's span ends inside the header.
///
/// Spec F 3.3.1 says it runs to the end of the header, and on every block
/// without an embedded comment that is exactly right. An OLD-STYLE comment
/// (3.3.9) is a block embedded INSIDE the header it belongs to, and the
/// writer computes the header's checksum BEFORE appending it: the span
/// ends where the comment starts.
///
/// PROVEN, and proven in the only way a 16 bit value can be: the alternative
/// span matches EXACTLY, on five headers of three archives, where the whole
/// header matches none of them.
///
/// | Archive | Block | Stored | Span that matches |
/// |---|---|---|---|
/// | `rar202/comment_nopsw.rar` | main, size 51 | `0x01bd` | 2..13 |
/// | `rar202/comment_nopsw.rar` | two files, size 66 | `0xcf6d`, `0x2f58` | 2..41, the name's end |
/// | `rar202/comment_psw.rar` | main, size 51 | `0x01bd` | 2..13 |
/// | a generated comments archive | comment 0x75, size 24 | `0x6a59` | 2..13 |
/// | a generated comments archive | file, size 54 | `0x8c5f` | 2..43, the name's end |
///
/// Spec F 3.3.9 records the first archive's headers as simply not matching
/// and leaves question 7 to settle it with a genuine writer. They match;
/// the span is what differs. An erratum to the specification, not made yet.
pub(crate) fn checksum_end(head: &[u8], common: &Common) -> usize {
    let size = usize::from(common.size).min(head.len());
    let end = match common.btype {
        T_MAIN if common.flags & MF_COMMENT != 0 => MAIN_FIXED,
        T_COMMENT => COMMENT_FIXED,
        T_FILE | SERVICE_BLOCK if common.flags & FF_COMMENT != 0 => {
            file_name_end(head, common.flags).unwrap_or(size)
        }
        _ => size,
    };
    end.clamp(2, size)
}

/// Where a file header's name ends, which is where an embedded comment
/// begins. `None` when the header is too short to hold what it declares.
fn file_name_end(head: &[u8], flags: u16) -> Option<usize> {
    let name_len = usize::from(u16::from_le_bytes([*head.get(26)?, *head.get(27)?]));
    let fixed: usize = if flags & HIGH_SIZE_HALVES_PRESENT != 0 {
        40
    } else {
        32
    };
    fixed.checked_add(name_len)
}

/// The main archive header (type 0x73).
pub(crate) fn parse_main(head: &[u8], common: &Common, at: u64) -> Result<Fields> {
    let flags = common.flags;
    let mut main = Main {
        flags: u64::from(flags),
        is_volume: flags & MF_VOLUME != 0,
        volume_number: None,
        solid: flags & MF_SOLID != 0,
        locked: flags & MF_LOCK != 0,
        recovery: flags & MF_RECOVERY != 0,
        headers_encrypted: flags & MF_ENC_HEADERS != 0,
        locator: None,
        comment: None,
    };
    // Thirteen bytes: the seven common ones, a reserved u16 and a reserved
    // u32. With the comment flag set the header is longer and carries an
    // embedded comment block.
    if flags & MF_COMMENT != 0 && head.len() > 13 {
        main.comment = parse_embedded_comment(&head[13..], at + 13);
    }
    Ok(Fields::Main(main))
}

/// An embedded old-style comment block (type 0x75), which never fails the
/// header that carries it: a comment this package cannot read is no
/// comment (spec F 8.2 item 6).
pub(crate) fn parse_embedded_comment(block: &[u8], at: u64) -> Option<CommentSpan> {
    let common = parse_common(block).ok()?;
    if common.btype != T_COMMENT {
        return None;
    }
    let size = usize::from(common.size);
    if size > block.len() || size < COMMON + 6 {
        return None;
    }
    let body = &block[COMMON..size];
    Some(CommentSpan {
        data: at + (COMMON + 6) as u64..at + size as u64,
        unpacked: u64::from(u16::from_le_bytes([body[0], body[1]])),
        version: body[2],
        method: body[3],
        // This family's method byte, which spells STORED 0x30 and the
        // five levels 0x31 to 0x35 (spec F 3.3.9's observation, and the
        // same spelling a file header uses). The unpack version beside it
        // picks the algorithm, exactly as it does for a member.
        codec: comment_codec(body[3], u32::from(body[2])),
    })
}

/// The algorithm a RAR 1.5 to 4.x comment's method byte and unpack
/// version name (spec F 3.3.5's table, reached from 3.3.9 and 3.2.9).
pub(crate) fn comment_codec(method: u8, unpack_version: u32) -> CommentCodec {
    if method == 0x30 {
        return CommentCodec::Stored;
    }
    match codec_for(unpack_version) {
        Some(Rar4Codec::Rar15) => CommentCodec::Rar15,
        Some(Rar4Codec::Rar20) => CommentCodec::Rar20,
        Some(Rar4Codec::Rar29) => CommentCodec::Rar29,
        None => CommentCodec::Missing,
    }
}

/// The end-of-archive record (type 0x7B).
pub(crate) fn parse_end(head: &[u8], common: &Common) -> Result<Fields> {
    let flags = common.flags;
    let mut at = COMMON;
    let archive_crc32 = if flags & EF_ARCHIVE_CRC != 0 {
        let v = take_u32(head, at)?;
        at += 4;
        Some(v)
    } else {
        None
    };
    let volume_number = if flags & EF_VOL_NUMBER != 0 {
        let bytes = head.get(at..at + 2).ok_or_else(corrupt)?;
        Some(u32::from(u16::from_le_bytes([bytes[0], bytes[1]])))
    } else {
        None
    };
    Ok(Fields::End(EndHdr {
        flags: u64::from(flags),
        next_follows: flags & EF_NEXT_VOLUME != 0,
        volume_number,
        archive_crc32,
    }))
}

/// Fill `out` with a file (0x74) or new-style subblock (0x7A) header, and
/// answer where the stored name is and whether it is in the two-part
/// Unicode encoding.
///
/// The header is written straight into the caller's slot and is never moved
/// afterwards. See [`FileHdr::empty`] for what that is worth.
///
/// EVERY field of `out` is written, so a slot still holding the PREVIOUS
/// member's header is safe to hand in. The exhaustive destructuring at the
/// foot of this function is what makes the COMPILER check that: a field
/// added to `FileHdr` and not assigned here fails to compile, where a
/// struct literal built inside the parser could only have been caught by a
/// test noticing one member's value on the next member.
///
/// On an error the slot holds a mixture of two members, so a caller that
/// gets `Err` must discard the block it sits in, which is what the walk
/// does.
pub(crate) fn parse_file_into(
    head: &[u8],
    common: &Common,
    at: u64,
    out: &mut FileHdr,
) -> Result<(Range<usize>, bool)> {
    let flags = common.flags;
    let size = usize::from(common.size);
    if size > head.len() {
        return Err(corrupt());
    }
    let head = &head[..size];
    let mut packed = u64::from(take_u32(head, 7)?);
    let mut unpacked = u64::from(take_u32(head, 11)?);
    let host = *head.get(15).ok_or_else(corrupt)?;
    let crc32 = take_u32(head, 16)?;
    let dos_time = take_u32(head, 20)?;
    let unpack_version = u32::from(*head.get(24).ok_or_else(corrupt)?);
    let method_code = u32::from(*head.get(25).ok_or_else(corrupt)?);
    let name_len = usize::from(u16::from_le_bytes([
        *head.get(26).ok_or_else(corrupt)?,
        *head.get(27).ok_or_else(corrupt)?,
    ]));
    let attributes = take_u32(head, 28)?;
    let mut cursor = 32usize;
    if flags & HIGH_SIZE_HALVES_PRESENT != 0 {
        packed |= u64::from(take_u32(head, 32)?) << 32;
        unpacked |= u64::from(take_u32(head, 36)?) << 32;
        cursor = 40;
    }
    let name_end = cursor.checked_add(name_len).ok_or_else(corrupt)?;
    if name_end > head.len() {
        return Err(corrupt());
    }
    let name = cursor..name_end;
    cursor = name_end;

    let rar4_salt = if flags & FF_SALT != 0 {
        let bytes: [u8; 8] = head
            .get(cursor..cursor + 8)
            .ok_or_else(corrupt)?
            .try_into()
            .map_err(|_| corrupt())?;
        cursor += 8;
        Some(bytes)
    } else {
        None
    };

    let mut mtime = dostime::from_dos(dos_time);
    if flags & FF_EXT_TIME != 0 {
        // The header size bounds the area, so a malformed group costs
        // nothing: the DOS time stands.
        mtime = dostime::read_extended(&head[cursor.min(head.len())..], mtime).or(mtime);
    }

    let dict_bits = (flags & FF_DICT_MASK) >> 5;
    // The directory rule of spec F 3.3.6, whose second arm is not a
    // defensive extra: a genuine DOS RAR 1.55 directory carries header
    // flags 0x8000 and nothing else, unpack version 15, sizes 0 and DOS
    // attribute 0x10. A reader that tests the flags word alone creates an
    // empty FILE where the directory should be (spec F 8.1 defect 1).
    let dos_attributes = matches!(host, 0..=2);
    let is_directory = dict_bits == DICT_DIRECTORY
        || (unpack_version < 20 && dos_attributes && attributes & 0x10 != 0);

    let method = if method_code == 0x30 {
        Method::Stored
    } else {
        Method::Compressed {
            level: (method_code & 0x0F) as u8,
            // The RAR 4 family's dictionary bits are 64 KiB shifted left by
            // the bit value; a directory's value 7 names no dictionary.
            dictionary: if dict_bits == DICT_DIRECTORY {
                64 * 1024
            } else {
                (64u64 * 1024) << dict_bits
            },
        }
    };

    let service = match common.btype {
        SERVICE_BLOCK => Some(ServiceName::from_name(&head[name.clone()])),
        _ => None,
    };

    // A per-file old-style comment sits where the name ends (3.3.9), which
    // is also where the header's checksum span stops.
    let comment = if flags & FF_COMMENT != 0 && name_end < head.len() {
        parse_embedded_comment(&head[name_end..], at + name_end as u64)
    } else {
        None
    };

    // Every field of the caller's slot is assigned, and the compiler is
    // what checks it: see this function's own documentation.
    let FileHdr {
        name: out_name,
        raw_name: out_raw_name,
        file_flags: out_file_flags,
        dict_bits: out_dict_bits,
        host_raw: out_host_raw,
        raw_checksum: out_raw_checksum,
        service: out_service,
        is_directory: out_is_directory,
        unpacked_size: out_unpacked_size,
        packed_size: out_packed_size,
        split_before: out_split_before,
        split_after: out_split_after,
        encrypted: out_encrypted,
        solid: out_solid,
        mtime: out_mtime,
        header_mtime: out_header_mtime,
        attributes: out_attributes,
        host_os: out_host_os,
        checksum: out_checksum,
        method: out_method,
        dictionary: out_dictionary,
        method_code: out_method_code,
        unpack_version: out_unpack_version,
        rar4_salt: out_rar4_salt,
        crypt: out_crypt,
        comment: out_comment,
        recovery_percent: out_recovery_percent,
        redirect: out_redirect,
        version: out_version,
    } = out;
    // The name span is the caller's to fill from its own arena.
    *out_name = 0..0;
    *out_raw_name = name.start as u32..name.end as u32;
    *out_file_flags = u64::from(flags);
    *out_dict_bits = dict_bits;
    *out_host_raw = host;
    *out_raw_checksum = crc32;
    *out_service = service;
    *out_is_directory = is_directory;
    // A header declares NO size when its unpacked size is all ones: with
    // the two high halves present, both halves `FFFFFFFF`; without them,
    // the low field `FFFFFFFF` (spec F 3.5.4 J6). It is what genuine rar
    // 5.50 and 6.24 wrote in every fragment header but the last of a
    // member read from standard input and split, whose last header alone
    // has the size. Every other value of the two fields is a declared
    // size, low `FFFFFFFF` over a high half of 0 among them.
    let all_ones = if flags & HIGH_SIZE_HALVES_PRESENT != 0 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    *out_unpacked_size = (unpacked != all_ones).then_some(unpacked);
    *out_packed_size = packed;
    *out_split_before = flags & FF_SPLIT_BEFORE != 0;
    *out_split_after = flags & FF_SPLIT_AFTER != 0;
    *out_encrypted = flags & FF_ENCRYPTED != 0;
    *out_solid = flags & FF_SOLID != 0;
    *out_mtime = mtime;
    *out_header_mtime = mtime;
    *out_attributes = attributes;
    *out_host_os = host_os(host);
    *out_checksum = Some(Checksum::Crc32(crc32));
    *out_method = method;
    // A STORED member declares a dictionary here too, and reference
    // `unrar lt` prints it: every file member of the genuine
    // `d155_m0.rar`, `d250_m0.rar` and `d140_m0.rar` lists as
    // `-m0 -md=64k`. A directory's bits hold the value 7, which marks the
    // directory and names no size, and the reference prints no `-md=`
    // clause for one.
    *out_dictionary = (!is_directory).then(|| (64u64 * 1024) << dict_bits);
    *out_method_code = method_code;
    *out_unpack_version = unpack_version;
    *out_rar4_salt = rar4_salt;
    *out_crypt = None;
    *out_comment = comment;
    *out_recovery_percent = None;
    // Spec F 3.3.6: the flag marks an older version of a file, whose
    // number, if it has one, is in the stored name.
    *out_version = if service.is_none() && flags & FF_VERSION != 0 {
        crate::read::block::VERSION_IN_NAME
    } else {
        0
    };
    // Spec F 3.3.12: the family's one redirection, a Unix symbolic link
    // whose target is the member's CONTENT. Host 3 and the link type in
    // the mode's file type bits, on a member that is not a directory. A
    // target above 64 KiB is never read (`Corrupt(Redirection)` at
    // extraction), because no host's path limit comes near it.
    *out_redirect =
        (service.is_none() && host == 3 && attributes & 0xF000 == 0xA000 && !is_directory)
            .then_some(crate::read::block::Redirect {
                code: 1,
                dir: false,
                target_start: 0,
                target_len: 0,
                fault: unpacked > crate::read::block::RAR4_LINK_MAX,
                in_content: true,
            });
    let _ = at;
    Ok((name, flags & FF_UNICODE != 0))
}

/// Host OS: 0 MS-DOS, 1 OS/2, 2 Win32, 3 Unix, 4 MacOS, 5 BeOS.
pub(crate) fn host_os(raw: u8) -> HostOs {
    match raw {
        0 => HostOs::MsDos,
        1 => HostOs::Os2,
        2 => HostOs::Windows,
        3 => HostOs::Unix,
        4 => HostOs::MacOs,
        5 => HostOs::BeOs,
        n => HostOs::Other(n),
    }
}

fn take_u32(head: &[u8], at: usize) -> Result<u32> {
    let bytes = head.get(at..at + 4).ok_or_else(corrupt)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Which decoder an unpack version selects (spec F 3.3.5). A version this
/// table does not name is `Unsupported(Version)` for that member and for no
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rar4Codec {
    /// RAR 1.5, spec A.
    Rar15,
    /// RAR 2.0, spec D.
    Rar20,
    /// RAR 2.9 / 3.x / 4.x, spec H, with spec I and spec J behind it.
    Rar29,
}

/// The decoder for `unpack_version`, or `None` when no table row names it.
///
/// Only 29 is the RAR 2.9 decoder. Every version above it is one this
/// package does not know, as reference unrar 7.23 does not ("Unknown
/// method", exit 2): spec F 3.3.5, decided 28 Sep 2026,
/// where the table's row had read "29 and above".
pub(crate) fn codec_for(unpack_version: u32) -> Option<Rar4Codec> {
    match unpack_version {
        13..=15 => Some(Rar4Codec::Rar15),
        20 | 26 => Some(Rar4Codec::Rar20),
        29 => Some(Rar4Codec::Rar29),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::block::FileHdr;

    /// A RAR 1.5 to 4.x file header over `flags`, the name and whatever
    /// the flags say follows it. The checksum field is left at zero: the
    /// header's own checksum is the block reader's business, not this
    /// parser's.
    fn file_header(
        flags: u16,
        name: &[u8],
        unpack_version: u8,
        method: u8,
        attributes: u32,
    ) -> Vec<u8> {
        let mut head = vec![0u8; 2];
        head.push(T_FILE);
        head.extend_from_slice(&flags.to_le_bytes());
        head.extend_from_slice(&[0, 0]); // the size, filled in below
        head.extend_from_slice(&64u32.to_le_bytes()); // the packed size
        head.extend_from_slice(&128u32.to_le_bytes()); // the unpacked size
        head.push(3); // the host, Unix
        head.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // the CRC32
        head.extend_from_slice(&0x5123_4567u32.to_le_bytes()); // the DOS time
        head.push(unpack_version);
        head.push(method);
        head.extend_from_slice(&(name.len() as u16).to_le_bytes());
        head.extend_from_slice(&attributes.to_le_bytes());
        head.extend_from_slice(name);
        if flags & FF_SALT != 0 {
            head.extend_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2]);
        }
        let size = head.len() as u16;
        head[5..7].copy_from_slice(&size.to_le_bytes());
        head
    }

    fn parse_into(head: &[u8], out: &mut FileHdr) -> bool {
        let common = parse_common(head).expect("the built header parses");
        let (_, unicode) = parse_file_into(head, &common, 0, out).expect("the built header parses");
        unicode
    }

    /// Spec F 3.3.12: host 3 and the link type in the mode make a link, a
    /// directory never is one, another host's word is not a mode, and a
    /// target above 64 KiB is marked for `Corrupt(Redirection)`.
    #[test]
    fn a_unix_link_is_known_by_its_host_and_mode() {
        let link = |unpacked: u32, host: u8, flags: u16| {
            let mut head = file_header(flags, b"sym", 20, 0x30, 0xA1FF);
            head[11..15].copy_from_slice(&unpacked.to_le_bytes());
            head[15] = host;
            let mut out = FileHdr::empty();
            parse_into(&head, &mut out);
            out.redirect
        };
        let r = link(5, 3, 0).expect("a Unix link");
        assert_eq!(r.kind(), crate::read::RedirectionKind::PosixSymlink);
        assert!(r.in_content && !r.dir && !r.fault);
        assert!(!link(64 * 1024, 3, 0).expect("a link").fault);
        assert!(link(64 * 1024 + 1, 3, 0).expect("a link").fault);
        assert_eq!(link(5, 2, 0), None, "a Windows host's word is not a mode");
        assert_eq!(link(5, 3, DICT_DIRECTORY << 5), None, "a directory");
        // And a reused slot forgets it.
        let mut out = FileHdr::empty();
        let mut head = file_header(0, b"sym", 20, 0x30, 0xA1FF);
        head[15] = 3;
        parse_into(&head, &mut out);
        assert!(out.redirect.is_some());
        parse_into(&file_header(0, b"f", 20, 0x30, 0x81A4), &mut out);
        assert_eq!(out.redirect, None);
    }

    /// The parser fills a caller-owned slot, so a field it forgot to write
    /// would carry the PREVIOUS member's value into this one. The
    /// exhaustive destructuring in `parse_file_into` is what makes that a
    /// compile error; this test is the behavioural half, over the fields
    /// this family's flags word turns on and off.
    #[test]
    fn a_reused_slot_carries_nothing_of_the_member_before_it() {
        let rich = file_header(
            FF_SPLIT_BEFORE
                | FF_SPLIT_AFTER
                | FF_ENCRYPTED
                | FF_SOLID
                | FF_SALT
                | FF_UNICODE
                | (DICT_DIRECTORY << 5),
            b"dir",
            29,
            0x33,
            0,
        );
        let plain = file_header(0, b"bb", 20, 0x30, 0);

        let mut reused = FileHdr::empty();
        assert!(parse_into(&rich, &mut reused), "the rich name is Unicode");
        // The rich header really does set what the plain one clears,
        // without which the test below would pass on any parser at all.
        assert!(reused.rar4_salt.is_some(), "the rich header carries a salt");
        assert!(reused.split_before && reused.split_after);
        assert!(reused.encrypted && reused.solid && reused.is_directory);

        assert!(!parse_into(&plain, &mut reused), "the plain name is not");
        let mut fresh = FileHdr::empty();
        parse_into(&plain, &mut fresh);

        assert!(reused.rar4_salt.is_none(), "the salt is the member's own");
        assert!(!reused.split_before && !reused.split_after);
        assert!(!reused.encrypted && !reused.solid && !reused.is_directory);
        assert_eq!(reused.rar4_salt, fresh.rar4_salt);
        assert_eq!(reused.file_flags, fresh.file_flags);
        assert_eq!(reused.dict_bits, fresh.dict_bits);
        assert_eq!(reused.dictionary, fresh.dictionary);
        assert_eq!(reused.method, fresh.method);
        assert_eq!(reused.method_code, fresh.method_code);
        assert_eq!(reused.unpack_version, fresh.unpack_version);
        assert_eq!(reused.raw_name, fresh.raw_name);
        assert_eq!(reused.mtime, fresh.mtime);
        assert_eq!(reused.header_mtime, fresh.header_mtime);
        assert_eq!(reused.attributes, fresh.attributes);
        assert_eq!(reused.host_raw, fresh.host_raw);
        assert_eq!(reused.host_os, fresh.host_os);
        assert_eq!(reused.checksum, fresh.checksum);
        assert_eq!(reused.raw_checksum, fresh.raw_checksum);
        assert_eq!(reused.packed_size, fresh.packed_size);
        assert_eq!(reused.unpacked_size, fresh.unpacked_size);
        assert_eq!(reused.service, fresh.service);
    }

    /// What the parser hands BACK is pinned, because the whole point of
    /// the in-place form is that nothing header-sized travels by value:
    /// a return type that grew back to header size would put the copy
    /// back with no other test failing.
    #[test]
    fn the_parser_hands_back_nothing_header_sized() {
        // Taken from the FUNCTION'S OWN signature rather than from a type
        // written out here, so that widening what the parser returns fails
        // this test instead of leaving it measuring a type nothing uses.
        fn returned_size<T>(_: fn(&[u8], &Common, u64, &mut FileHdr) -> Result<T>) -> usize {
            std::mem::size_of::<T>()
        }
        let returned = returned_size(parse_file_into);
        let header = std::mem::size_of::<FileHdr>();
        assert!(returned <= 24, "the name range and one flag: {returned}");
        // Non-vacuity: the bound above says something only because the
        // header it replaces is an order of magnitude larger.
        assert!(
            header >= 10 * returned,
            "the header is {header} bytes and the return is {returned}"
        );
    }
}
