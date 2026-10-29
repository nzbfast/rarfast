//! Reading just enough of an existing block header to rewrite it: the
//! service name a block carries, and a member header with a different
//! NAME and nothing else changed.
//!
//! **Why a splice and not a rebuild.** A rewrite that rebuilt a member
//! header from what the reader reports would have to reproduce every
//! field the original carried - the compression information, the solid
//! bit, the hash record, the encryption record, a service block's own
//! parameter, any extra record this crate does not model - and would
//! silently drop whatever it did not know about. Everything here instead
//! keeps the original bytes and replaces ONE field, so a header that
//! carried something unknown carries it still, and the only ways the
//! output can differ from the input are the name, the name length, the
//! header length and the header checksum.

use crate::write::consts::*;
use crate::write::{rar4, rar5};

/// Reads a vint, returning it and the offset after it.
fn vint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut at = at;
    loop {
        let byte = *bytes.get(at)?;
        at += 1;
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, at));
        }
    }
}

/// Whether a RAR 5 block of any type says it depends on the block before
/// it (block flag 0x0020, spec F 3.2.4): a stream, an access list or an
/// owner record of the member it follows. Only the fields every block
/// header opens with are read, so a type this crate does not model
/// answers too; a header too short to hold them answers no.
pub(crate) fn rar5_depends_on_previous(header: &[u8]) -> bool {
    let flags = (|| {
        let (_size, at) = vint(header, 4)?;
        let (_kind, at) = vint(header, at)?;
        Some(vint(header, at)?.0)
    })();
    flags.is_some_and(|flags| flags & BLOCK_DEPENDS_ON_PREVIOUS != 0)
}

/// Where a RAR 5 block header's fields sit, for the two jobs above.
struct Rar5Parts {
    kind: u64,
    flags: u64,
    /// The data area's declared size and the width it was written in, so
    /// a reserved width survives the rewrite.
    data: Option<(u64, usize)>,
    /// Where the type-specific area starts.
    specific: usize,
    /// The file flags vint, and the unpacked size that follows it: both
    /// are re-emitted rather than copied, because the rewrite form takes
    /// the unpacked size in its natural width too (spec G 3.6.5).
    file_flags: u64,
    unpacked: u64,
    /// Where the attributes vint starts, which is the first byte of the
    /// type-specific area that a rewrite copies unchanged.
    attributes_at: usize,
    /// Where the name length vint starts, and where the name starts.
    name_len_at: usize,
    name_at: usize,
    name_len: usize,
    /// The extra area, as a range in the header image.
    extra: std::ops::Range<usize>,
}

/// RAR 5 block flag: an extra area follows the type-specific area.
const HAS_EXTRA_AREA: u64 = 0x0001;
/// RAR 5 block flag: a data area follows the header.
const HAS_DATA_AREA: u64 = 0x0002;
/// RAR 5 file flag: the header carries a modification time.
const FILE_HAS_MTIME: u64 = 0x0002;
/// RAR 5 file flag: the header carries a CRC32 of the member's data.
const FILE_HAS_CRC32: u64 = 0x0004;

/// Parses a RAR 5 file or service header far enough to find its name.
fn rar5_parts(header: &[u8]) -> Option<Rar5Parts> {
    // The checksum, then the header's own length, which is what the
    // checksum covers together with the body (spec G 3.2).
    let (hsize, body) = vint(header, 4)?;
    let end = body.checked_add(usize::try_from(hsize).ok()?)?;
    if end > header.len() {
        return None;
    }
    let (kind, at) = vint(header, body)?;
    let (flags, at) = vint(header, at)?;
    let (extra_len, at) = if flags & HAS_EXTRA_AREA != 0 {
        let (value, at) = vint(header, at)?;
        (usize::try_from(value).ok()?, at)
    } else {
        (0, at)
    };
    let (data, at) = if flags & HAS_DATA_AREA != 0 {
        let before = at;
        let (value, at) = vint(header, at)?;
        (Some((value, at - before)), at)
    } else {
        (None, at)
    };
    let specific = at;
    // The type-specific area of a file (2) or service (3) header.
    let (file_flags, at) = vint(header, at)?;
    let (unpacked, at) = vint(header, at)?;
    let attributes_at = at;
    let (_attributes, mut at) = vint(header, at)?;
    if file_flags & FILE_HAS_MTIME != 0 {
        at = at.checked_add(4)?;
    }
    if file_flags & FILE_HAS_CRC32 != 0 {
        at = at.checked_add(4)?;
    }
    let (_compression, at) = vint(header, at)?;
    let (_host, name_len_at) = vint(header, at)?;
    let (name_len, name_at) = vint(header, name_len_at)?;
    let name_len = usize::try_from(name_len).ok()?;
    let extra_start = end.checked_sub(extra_len)?;
    if name_at.checked_add(name_len)? != extra_start {
        // The name does not run up to the extra area, so this header is
        // not laid out the way the format says and nothing is spliced
        // into it.
        return None;
    }
    Some(Rar5Parts {
        kind,
        flags,
        data,
        specific,
        file_flags,
        unpacked,
        attributes_at,
        name_len_at,
        name_at,
        name_len,
        extra: extra_start..end,
    })
}

/// The name a RAR 5 file or service header carries, as stored.
pub(crate) fn rar5_name(header: &[u8]) -> Option<&[u8]> {
    let parts = rar5_parts(header)?;
    header.get(parts.name_at..parts.name_at + parts.name_len)
}

/// The same RAR 5 header, re-emitted in the REWRITE form of spec G 3.6.5:
/// the data size field in its NATURAL width rather than the wider one the
/// reference reserves for a member it is about to stream.
///
/// The reference does this to every member it re-emits, and it is where
/// the last bytes between a rewrite and the reference's own output sit: a
/// header the writer laid down at 35 bytes comes back at 33. Everything
/// else is the caller's original bytes, exactly as in [`rar5_renamed`].
///
/// `None` when the header is not laid out the way the format says, and
/// the caller then copies it verbatim rather than guessing.
pub(crate) fn rar5_rewritten(header: &[u8]) -> Option<Vec<u8>> {
    let parts = rar5_parts(header)?;
    let specific = rewrite_specific(
        header,
        &parts,
        header.get(parts.name_len_at..parts.name_at + parts.name_len)?,
    )?;
    Some(rar5::frame(
        parts.kind,
        parts.flags & !(HAS_EXTRA_AREA | HAS_DATA_AREA),
        parts
            .data
            .map(|(size, _)| (size, rar5::vint_width_of(size))),
        &specific,
        header.get(parts.extra.clone())?,
    ))
}

/// The type-specific area in the REWRITE form: the file flags and the
/// UNPACKED size re-emitted at their natural widths, everything from the
/// attributes to the host byte copied, and `tail` as the name field.
///
/// Spec G 3.6.5: a rewrite changes the two size fields and nothing else
/// in this area. The compression information stays as wide as it was, and
/// the modification time stays where it was held, a whole second in the
/// header's own field with its flag set.
fn rewrite_specific(header: &[u8], parts: &Rar5Parts, tail: &[u8]) -> Option<Vec<u8>> {
    let mut specific = Vec::with_capacity(parts.name_at - parts.specific + tail.len() + 4);
    rar5::put_vint(&mut specific, parts.file_flags);
    rar5::put_vint(&mut specific, parts.unpacked);
    specific.extend_from_slice(header.get(parts.attributes_at..parts.name_len_at)?);
    specific.extend_from_slice(tail);
    Some(specific)
}

/// The same RAR 5 header with `name` in place of the one it carries.
///
/// Everything else - the block flags, the reserved width of the data
/// size field, the type-specific fields and the whole extra area - is the
/// caller's original bytes.
pub(crate) fn rar5_renamed(header: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let parts = rar5_parts(header)?;
    let mut tail = Vec::with_capacity(name.len() + 4);
    rar5::put_vint(&mut tail, name.len() as u64);
    tail.extend_from_slice(name);
    let specific = rewrite_specific(header, &parts, &tail)?;
    Some(rar5::frame(
        parts.kind,
        // `frame` puts the extra-area and data-area bits back itself from
        // what it is given, so they are cleared here rather than set twice.
        parts.flags & !(HAS_EXTRA_AREA | HAS_DATA_AREA),
        // The natural width, which is the REWRITE form of spec G 3.6.5:
        // a re-emitted member does not keep the reserve the writer made
        // for one it was about to stream.
        parts
            .data
            .map(|(size, _)| (size, rar5::vint_width_of(size))),
        &specific,
        header.get(parts.extra.clone())?,
    ))
}

/// Where a RAR 4 family file header's name sits (spec G 3.14.3).
///
/// The body runs from the byte after the header's own size field, or
/// after the 4 byte data size when the flags carry one.
struct Rar4Parts {
    kind: u8,
    flags: u16,
    data_size: Option<u32>,
    body: usize,
    name_size_at: usize,
    name_at: usize,
    name_len: usize,
    head_end: usize,
}

/// RAR 4 file flag: the 64 bit size fields are present.
const R4_HIGH_SIZES: u16 = 0x0100;

fn rar4_parts(header: &[u8]) -> Option<Rar4Parts> {
    let kind = *header.get(2)?;
    let flags = u16::from_le_bytes([*header.get(3)?, *header.get(4)?]);
    let head_size = usize::from(u16::from_le_bytes([*header.get(5)?, *header.get(6)?]));
    if head_size > header.len() || head_size < 7 {
        return None;
    }
    let (data_size, body): (Option<u32>, usize) = if flags & R4_HAS_DATA != 0 {
        let raw = header.get(7..11)?;
        (
            Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
            11,
        )
    } else {
        (None, 7)
    };
    // unpacked size 4, host 1, crc32 4, dos time 4, version 1, method 1.
    let name_size_at = body.checked_add(15)?;
    let name_len = usize::from(u16::from_le_bytes([
        *header.get(name_size_at)?,
        *header.get(name_size_at + 1)?,
    ]));
    // attributes 4, then the high size fields when the flags say so.
    let mut name_at = name_size_at.checked_add(2 + 4)?;
    if flags & R4_HIGH_SIZES != 0 {
        name_at = name_at.checked_add(8)?;
    }
    if name_at.checked_add(name_len)? > head_size {
        return None;
    }
    Some(Rar4Parts {
        kind,
        flags,
        data_size,
        body,
        name_size_at,
        name_at,
        name_len,
        head_end: head_size,
    })
}

/// The same RAR 4 family header with `name` in place of the one it
/// carries; everything after the name (a salt, an extended time record)
/// is kept.
pub(crate) fn rar4_renamed(header: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let parts = rar4_parts(header)?;
    if name.len() > usize::from(u16::MAX) {
        return None;
    }
    let mut body = Vec::with_capacity(parts.head_end - parts.body + name.len());
    body.extend_from_slice(header.get(parts.body..parts.name_size_at)?);
    body.extend_from_slice(&(name.len() as u16).to_le_bytes());
    body.extend_from_slice(header.get(parts.name_size_at + 2..parts.name_at)?);
    body.extend_from_slice(name);
    body.extend_from_slice(header.get(parts.name_at + parts.name_len..parts.head_end)?);
    // The header's own length is a 16 bit field over all of it, and the
    // original may carry more beside the name than the Writer ever does.
    if parts.body + body.len() > usize::from(u16::MAX) {
        return None;
    }
    Some(rar4::frame(parts.kind, parts.flags, parts.data_size, &body))
}

/// The name a RAR 4 family file header carries, as stored.
pub(crate) fn rar4_name(header: &[u8]) -> Option<&[u8]> {
    let parts = rar4_parts(header)?;
    header.get(parts.name_at..parts.name_at + parts.name_len)
}

/// Whether a RAR 5 service block is the quick-open index (spec G 3.6.6).
pub(crate) fn is_quick_open(header: &[u8], rar5_family: bool) -> bool {
    let name = if rar5_family {
        rar5_name(header)
    } else {
        rar4_name(header)
    };
    name == Some(SERVICE_QUICK_OPEN)
}
