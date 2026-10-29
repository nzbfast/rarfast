//! RAR 5 header fields (spec F 3.2). Pure functions over one header's
//! bytes: the framing and the reads that produced those bytes are the block
//! reader's business.

use crate::crypto::{Rar5Record, FLAG_CHECK};
use crate::error::{Corruption, Error, ErrorKind, Result};
use crate::read::block::{EndHdr, Fields, FileHdr, Locator, Main, Redirect, ServiceName};
use crate::read::{htime, vint};
use crate::types::{Checksum, HostOs, Method, Timestamp};

/// Header types (spec F 3.2.3).
pub(crate) const TYPE_MAIN: u64 = 1;
pub(crate) const TYPE_FILE: u64 = 2;
pub(crate) const TYPE_SERVICE: u64 = 3;
pub(crate) const TYPE_ENCRYPTION: u64 = 4;
pub(crate) const TYPE_END: u64 = 5;

/// Header flags common to every block (spec F 3.2.4).
pub(crate) const HF_EXTRA: u64 = 0x0001;
pub(crate) const HF_DATA: u64 = 0x0002;
pub(crate) const HF_SPLIT_BEFORE: u64 = 0x0008;
pub(crate) const HF_SPLIT_AFTER: u64 = 0x0010;

/// Archive flags (spec F 3.2.5).
pub(crate) const AF_VOLUME: u64 = 0x0001;
pub(crate) const VOLUME_NUMBER_PRESENT: u64 = 0x0002;
pub(crate) const AF_SOLID: u64 = 0x0004;
pub(crate) const AF_RECOVERY: u64 = 0x0008;
pub(crate) const AF_LOCKED: u64 = 0x0010;

/// File flags (spec F 3.2.6).
pub(crate) const FF_DIRECTORY: u64 = 0x0001;
pub(crate) const MODIFICATION_TIME_PRESENT: u64 = 0x0002;
pub(crate) const FF_CRC32: u64 = 0x0004;
pub(crate) const FF_UNKNOWN_SIZE: u64 = 0x0008;

/// Extra record types, main header.
pub(crate) const XM_LOCATOR: u64 = 1;
/// Extra record types, file and service headers.
pub(crate) const XF_CRYPT: u64 = 1;
pub(crate) const XF_HASH: u64 = 2;
pub(crate) const XF_TIME: u64 = 3;
pub(crate) const XF_VERSION: u64 = 4;
pub(crate) const XF_REDIRECT: u64 = 5;
pub(crate) const RECOVERY_PERCENTAGE: u64 = 7;

/// The one RAR 5 hash record type this package knows.
pub(crate) const HASH_BLAKE2SP: u64 = 0;

/// The largest dictionary a RAR 5 member may declare: 64 GiB, version 1's
/// power 19 with no fraction (spec F 3.2.6.3, consequence 4).
pub(crate) const MAX_DICTIONARY: u64 = 64 << 30;

/// A RAR 5 compression information field's ALGORITHM and DICTIONARY (spec
/// F 3.2.6 and 3.2.6.3), or the `Unsupported(Version)` a version this
/// reader does not know answers.
///
/// - Version 0: the dictionary is 128 KiB shifted left by bits 10 to 13;
///   bits 14 and up are ignored, as the reference ignores them.
/// - Version 1 (RAR 7, "v70"): the power is bits 10 to 14 and a fraction
///   in 32nds is bits 15 to 19, so the dictionary is `base + (base / 32) *
///   fraction` with `base = 128 KiB << power`, at every power. Bit 20 says
///   the data is in the version 0 ALGORITHM under that dictionary; bits 21
///   and up are ignored. A dictionary above [`MAX_DICTIONARY`] is a field
///   no writer can produce and the reference does not read, and is treated
///   as the unknown version it then is: `Unsupported(Version(1))`.
/// - Any other version: `Unsupported(Version)`.
///
/// The arithmetic is in `u64` and exact: power 31 with fraction 31 is below
/// 2^55, and `base / 32` divides exactly because `base` is at least 128 KiB.
pub(crate) fn dictionary_of(comp: u64) -> Result<(u32, u64)> {
    const BASE: u64 = 128 * 1024;
    let version = (comp & 0x3F) as u32;
    let unknown = |version| {
        Err(Error::new(ErrorKind::Unsupported(
            crate::error::Unsupported::Version(version),
        )))
    };
    match version {
        0 => Ok((0, BASE << ((comp >> 10) & 0x0F))),
        1 => {
            let base = BASE << ((comp >> 10) & 0x1F);
            let dictionary = base + (base / 32) * ((comp >> 15) & 0x1F);
            if dictionary > MAX_DICTIONARY {
                return unknown(1);
            }
            let algorithm = if comp & (1 << 20) != 0 { 0 } else { 1 };
            Ok((algorithm, dictionary))
        }
        other => unknown(other),
    }
}

fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Header))
}

/// The fields every RAR 5 block begins with.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Common {
    /// The stored header CRC32.
    pub crc: u32,
    /// Total header bytes, from the CRC field to the end of the extra area.
    pub head_len: usize,
    /// The header type.
    pub btype: u64,
    /// The header flags.
    pub flags: u64,
    /// The extra area's size, 0 when flag 0x0001 is clear.
    pub extra_size: u64,
    /// The data area's size, 0 when flag 0x0002 is clear.
    pub data_size: u64,
    /// The first byte of the type-specific fields.
    pub at: usize,
}

impl Common {
    /// Where the extra area starts, which is the header END minus the extra
    /// area size and NOT a fixed offset: the type-specific fields in front
    /// of it are variable length.
    pub(crate) fn extra_start(&self) -> Result<usize> {
        let size = usize::try_from(self.extra_size).map_err(|_| corrupt())?;
        self.head_len.checked_sub(size).ok_or_else(corrupt)
    }
}

/// Parse the common fields of the header in `head` (exactly one header's
/// bytes, CRC field included).
pub(crate) fn parse_common(head: &[u8]) -> Result<Common> {
    if head.len() < 5 {
        return Err(corrupt());
    }
    let crc = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let mut at = 4;
    let size = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let head_len = (at as u64)
        .checked_add(size)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(corrupt)?;
    if head_len != head.len() {
        return Err(corrupt());
    }
    let btype = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let flags = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let extra_size = if flags & HF_EXTRA != 0 {
        vint::read(head, &mut at).ok_or_else(corrupt)?
    } else {
        0
    };
    let data_size = if flags & HF_DATA != 0 {
        vint::read(head, &mut at).ok_or_else(corrupt)?
    } else {
        0
    };
    let common = Common {
        crc,
        head_len,
        btype,
        flags,
        extra_size,
        data_size,
        at,
    };
    // The extra area must fit behind the fields already read.
    if common.extra_start()? < at {
        return Err(corrupt());
    }
    Ok(common)
}

/// The header checksum covers the header size field and everything after
/// it, up to and including the extra area: every byte from just after the
/// 4-byte CRC field to the end of the header (spec F 3.2.2).
pub(crate) fn header_checksum(head: &[u8]) -> u32 {
    crate::checksum::crc32(&head[4..])
}

/// Walk an extra area, calling `each(record type, body)` per record. An
/// unknown record is skipped by its own size; a record whose size runs past
/// the area is `Corrupt` and the walk stops there.
pub(crate) fn walk_extra(area: &[u8], each: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
    if walk_extra_while_sound(area, each)? {
        Ok(())
    } else {
        Err(corrupt())
    }
}

/// [`walk_extra`] for a FILE header, where a record that is not one ends
/// the walk of the AREA and not the walk of the archive: `false` when the
/// area holds a record with no size or no type, one whose size runs past
/// the area, or bytes behind the last record. The records in front of it
/// were handed to `each`; an error `each` answers is still the caller's.
///
/// Measured against unrar 7.23 on 9 Oct 2026 (SWEEP3-08OCT-14): a file
/// header with a right checksum whose extra area holds a record of size
/// 0, one whose size runs past the area, a stray byte behind the records
/// or an area size a few bytes short is read, and its member and every
/// later one test `OK`.
pub(crate) fn walk_extra_while_sound(
    area: &[u8],
    mut each: impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<bool> {
    let mut at = 0usize;
    while at < area.len() {
        let Some(size) = vint::read_usize(area, &mut at) else {
            return Ok(false);
        };
        // A size of 0 holds no type, so every record that parses moves
        // the walk on by at least one byte.
        let Some(rec) = at.checked_add(size).and_then(|end| area.get(at..end)) else {
            return Ok(false);
        };
        let mut rat = 0usize;
        let Some(rtype) = vint::read(rec, &mut rat) else {
            return Ok(false);
        };
        each(rtype, &rec[rat..])?;
        at += size;
    }
    Ok(true)
}

/// The main archive header (type 1). `main_at` is the source offset of the
/// header's first byte as stored, which the locator's offsets are measured
/// from: the first byte after the signature in an archive with clear
/// headers, and the first byte of the IV in front of the main header in
/// one whose headers are encrypted (spec F 3.2.8).
pub(crate) fn parse_main(head: &[u8], common: &Common, main_at: u64) -> Result<Fields> {
    let mut at = common.at;
    let flags = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let volume_number = if flags & VOLUME_NUMBER_PRESENT != 0 {
        let n = vint::read(head, &mut at).ok_or_else(corrupt)?;
        Some(u32::try_from(n).map_err(|_| corrupt())?)
    } else {
        None
    };
    let mut main = Main {
        flags,
        is_volume: flags & AF_VOLUME != 0,
        volume_number,
        solid: flags & AF_SOLID != 0,
        locked: flags & AF_LOCKED != 0,
        recovery: flags & AF_RECOVERY != 0,
        ..Main::default()
    };
    let extra = &head[common.extra_start()?..];
    walk_extra(extra, |rtype, body| {
        if rtype == XM_LOCATOR {
            main.locator = Some(parse_locator(body, main_at)?);
        }
        Ok(())
    })?;
    Ok(Fields::Main(main))
}

/// The locator, whose offsets are measured from the first byte of the main
/// header as stored (`main_at`) and are converted to source coordinates
/// here. An offset of 0 means "no such record": rar 7.23 writes a zero
/// quick open offset on every archive it writes.
pub(crate) fn parse_locator(body: &[u8], main_at: u64) -> Result<Locator> {
    let mut at = 0usize;
    let flags = vint::read(body, &mut at).ok_or_else(corrupt)?;
    let mut take = |present: bool| -> Result<(Option<u64>, Option<u64>)> {
        if !present {
            return Ok((None, None));
        }
        let raw = vint::read(body, &mut at).ok_or_else(corrupt)?;
        let here = match raw {
            0 => None,
            n => Some(main_at.checked_add(n).ok_or_else(corrupt)?),
        };
        Ok((Some(raw), here))
    };
    let (raw_quick_open, quick_open) = take(flags & 0x0001 != 0)?;
    let (raw_recovery, recovery) = take(flags & 0x0002 != 0)?;
    Ok(Locator {
        flags,
        raw_quick_open,
        raw_recovery,
        quick_open,
        recovery,
    })
}

/// The end-of-archive record (type 5).
pub(crate) fn parse_end(head: &[u8], common: &Common) -> Result<Fields> {
    let mut at = common.at;
    let flags = vint::read(head, &mut at).ok_or_else(corrupt)?;
    Ok(Fields::End(EndHdr {
        flags,
        next_follows: flags & 0x0001 != 0,
        volume_number: None,
        archive_crc32: None,
    }))
}

/// What [`parse_file`] returns beside the fields: where the name's stored
/// bytes are, so the reader can hand them to the arena.
///
/// The walk itself has no use for this: it hands `parse_file_into` a slot
/// of its own and nothing header-sized is returned at all. What is left is
/// the solid-chain lookahead of `read/ahead.rs`, which is behind the
/// `parallel` feature, and this module's own tests.
#[cfg(any(feature = "parallel", test))]
pub(crate) struct FileParse {
    /// The fields, with an empty name span the caller fills in.
    pub fields: FileHdr,
    /// The name's bytes within the header.
    // The one caller of the wrapper, `read/ahead.rs`, reads the fields
    // alone: the solid-chain lookahead has no arena to put a name in. The
    // field stays because what the wrapper returns is what the parse
    // produced, and the walk reads the same range through
    // `parse_file_into`.
    #[allow(dead_code)]
    pub name: std::ops::Range<usize>,
}

/// A file (type 2) or service (type 3) header: the same field layout, with
/// the meaning of a service record coming from its name.
///
/// A convenience over [`parse_file_into`] for the callers that are not on
/// the per-member path: it moves the 296 byte header once to hand it back.
#[cfg(any(feature = "parallel", test))]
pub(crate) fn parse_file(head: &[u8], common: &Common, data_start: u64) -> Result<FileParse> {
    let mut fields = FileHdr::empty();
    let name = parse_file_into(head, common, data_start, &mut fields)?;
    Ok(FileParse { fields, name })
}

/// Fill `out` with a file (type 2) or service (type 3) header, and answer
/// where the name's stored bytes are.
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
    data_start: u64,
    out: &mut FileHdr,
) -> Result<std::ops::Range<usize>> {
    let mut at = common.at;
    let fflags = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let unpacked = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let attributes = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let header_mtime = if fflags & MODIFICATION_TIME_PRESENT != 0 {
        let raw = take_u32(head, &mut at)?;
        Some(Timestamp {
            unix_seconds: i64::from(raw),
            nanos: 0,
        })
    } else {
        None
    };
    let mut checksum = if fflags & FF_CRC32 != 0 {
        Some(Checksum::Crc32(take_u32(head, &mut at)?))
    } else {
        None
    };
    let comp = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let host = vint::read(head, &mut at).ok_or_else(corrupt)?;
    let name_len = vint::read_usize(head, &mut at).ok_or_else(corrupt)?;
    let name_end = at.checked_add(name_len).ok_or_else(corrupt)?;
    let extra_start = common.extra_start()?;
    // A name whose length runs past the fields in front of the extra
    // area: unrar 7.23 reads the name as far as the header goes and the
    // area where the header says it is, and the member tests `OK`
    // (SWEEP3-08OCT-14, a length of 200 on a five byte name, measured 9
    // Oct 2026). The header is then not one a writer makes, and its
    // member must prove itself (`FileHdr::unsound`).
    let mut incoherent = false;
    let name_end = if name_end > extra_start {
        incoherent = true;
        name_end.min(head.len())
    } else {
        name_end
    };
    let name = at..name_end;

    // Version 1 is RAR 7's ("v70") and is KNOWN (spec F 3.2.6.3, SPEC-H2
    // 3.3). `version` from here on is the ALGORITHM the data is in,
    // which is what the decoder and the listing both want: a version 1
    // field with bit 20 set is version 0 data, and the reference lists it
    // `v50`.
    //
    // A version this package does not know (2 and up, or a version 1
    // field above 64 GiB) names no dictionary. It matters ONLY where a
    // codec would run: a DIRECTORY entry or a STORED member decodes
    // nothing, so its version is ignored and it opens, as reference unrar
    // opens it (decided 27 Sep 2026; fuzz, a
    // directory declaring version 3). A COMPRESSED member of such a
    // version is read and listed in full here and refused when it is
    // reached, THAT member only (spec F 3.2.6, decided 28 Sep 2026):
    // `extract::codec_of` refuses a compressed member naming no
    // dictionary, and the walk goes on to the next.
    let method_code = ((comp >> 7) & 0x07) as u32;
    let (version, dictionary) = match dictionary_of(comp) {
        Ok((version, dictionary)) => (version, Some(dictionary)),
        Err(_) => ((comp & 0x3F) as u32, None),
    };
    // The power alone, for the block dump: bits 10 to 13 at version 0,
    // 10 to 14 at version 1 (whose fraction the dictionary carries).
    let dict_bits = (comp >> 10) & if comp & 0x3F == 0 { 0x0F } else { 0x1F };
    let method = if method_code == 0 {
        Method::Stored
    } else {
        Method::Compressed {
            level: method_code as u8,
            // A compressed member with an unknown version names none: a
            // directory's data area is never decoded, and any other such
            // member is refused before a decoder is built.
            dictionary: dictionary.unwrap_or(0),
        }
    };

    let service = if common.btype == TYPE_SERVICE {
        Some(ServiceName::from_name(&head[name.clone()]))
    } else {
        None
    };

    let mut crypt = None;
    let mut recovery_percent = None;
    let mut times = None;
    let mut redirect = None;
    let mut file_version = 0u32;
    let whole = walk_extra_while_sound(&head[extra_start..], |rtype, body| {
        match rtype {
            // Spec F 3.2.6.4: a flags vint and the version number. A
            // number of 0 is no version (V4). Of two records the last
            // decides. A service is no file. A record too short to hold
            // both fields states no version and the header is read on:
            // unrar 7.23 tests such a member and the next `OK`
            // (SWEEP3-08OCT-14, measured 9 Oct 2026). The header is not
            // one a writer makes (`incoherent` below).
            XF_VERSION if service.is_none() => {
                let mut at = 0usize;
                let (Some(_), Some(number)) =
                    (vint::read(body, &mut at), vint::read(body, &mut at))
                else {
                    incoherent = true;
                    return Ok(());
                };
                // rar numbers versions from 1; a number that does not
                // fit the word below is refused with the record that
                // holds no number at all.
                file_version = u32::try_from(number)
                    .ok()
                    .filter(|&n| n != crate::read::block::VERSION_IN_NAME)
                    .ok_or_else(corrupt)?;
            }
            // Spec F 3.2.6.2. Nothing here fails the HEADER: a record the
            // engine cannot use is that member's `Corrupt(Redirection)`
            // at extraction, and the walk goes on. Two records in one
            // header: the last decides. A service header has no use for
            // one and ignores it.
            XF_REDIRECT if service.is_none() => {
                let base = body.as_ptr() as usize - head.as_ptr() as usize;
                redirect = Some(parse_redirect(body, base));
            }
            // A FILE header's record that this engine cannot use (a
            // version or an exponent it does not know, or bytes that do
            // not parse) refuses THAT member when it is reached, and the
            // walk goes on: unrar 7.23 extracts the archive's other
            // members and exits 2 (`Unknown encryption method`), or 3
            // for a record cut short (SWEEP3-08OCT-06 and 14, measured 9
            // Oct 2026). A service header's is refused as before. A
            // record cut short inside its CHECK record alone is usable:
            // `check_cut`.
            XF_CRYPT => {
                crypt = Some(match Rar5Record::parse(body, true) {
                    Ok(record) => record,
                    Err(refusal) if service.is_none() => {
                        check_cut(body).unwrap_or_else(|| Rar5Record::unusable(&refusal))
                    }
                    Err(refusal) => return Err(refusal),
                });
            }
            // On an `RR` service header the subdata record holds, as a
            // vint, the recovery percentage the archive was written with
            // (spec L 3.5.1: `03` for `-rr3`, `AC 02` for `-rr300`). A
            // body that is no vint, a zero, or a value past `u32`, states
            // none.
            RECOVERY_PERCENTAGE if service == Some(ServiceName::Recovery) => {
                recovery_percent = vint::read(body, &mut 0)
                    .and_then(|p| u32::try_from(p).ok())
                    .and_then(std::num::NonZeroU32::new);
            }
            // Spec F 3.2.6.1. Nothing here can fail: a record too short
            // for the times its flags declare, an unknown flag bit and
            // trailing bytes are all accepted, because the reference
            // accepts all three.
            XF_TIME => times = htime::parse(body).or(times),
            // A hash record cut short fails ITS member and the walk goes
            // on: unrar 7.23 says `<name> - checksum error` for it, tests
            // the next member `OK` and exits 3 (SWEEP3-08OCT-14, measured
            // 9 Oct 2026). The bytes the record does hold are kept and
            // the rest read as zero, a value no data hashes to by any
            // known means, so the member is delivered and fails.
            XF_HASH => {
                let mut bat = 0usize;
                let Some(kind) = vint::read(body, &mut bat) else {
                    incoherent = true;
                    return Ok(());
                };
                if kind == HASH_BLAKE2SP {
                    let held = &body[bat..body.len().min(bat + 32)];
                    let mut bytes = [0u8; 32];
                    bytes[..held.len()].copy_from_slice(held);
                    incoherent |= held.len() < 32;
                    checksum = Some(Checksum::Blake2sp(bytes));
                }
            }
            _ => {}
        }
        Ok(())
    })?;

    // Every field of the caller's slot is assigned, and the compiler is
    // what checks it: see this function's own documentation.
    let FileHdr {
        name: out_name,
        raw_name,
        file_flags,
        dict_bits: out_dict_bits,
        host_raw,
        raw_checksum,
        service: out_service,
        is_directory,
        unpacked_size,
        packed_size,
        split_before,
        split_after,
        encrypted,
        solid,
        mtime,
        header_mtime: out_header_mtime,
        attributes: out_attributes,
        host_os,
        checksum: out_checksum,
        method: out_method,
        dictionary: out_dictionary,
        method_code: out_method_code,
        unpack_version,
        rar4_salt,
        crypt: out_crypt,
        comment,
        recovery_percent: out_recovery_percent,
        redirect: out_redirect,
        version: out_version,
    } = out;
    // The name span is the caller's to fill from its own arena.
    *out_name = 0..0;
    *raw_name = name.start as u32..name.end as u32;
    *file_flags = fflags;
    *out_dict_bits = dict_bits as u16;
    *host_raw = u8::try_from(host).unwrap_or(u8::MAX);
    *raw_checksum = match checksum {
        Some(Checksum::Crc32(v)) => v,
        _ => 0,
    };
    *out_service = service;
    *is_directory = fflags & FF_DIRECTORY != 0;
    *unpacked_size = if fflags & FF_UNKNOWN_SIZE != 0 {
        None
    } else {
        Some(unpacked)
    };
    *packed_size = common.data_size;
    *split_before = common.flags & HF_SPLIT_BEFORE != 0;
    *split_after = common.flags & HF_SPLIT_AFTER != 0;
    *encrypted = crypt.is_some();
    *solid = comp & (1 << 6) != 0;
    // 3.2.6.1: where a header carries both the mtime field and a record
    // with the modification time, THE RECORD WINS, which is what reference
    // unrar 7.23 prints. Usually only one of the two is there at all:
    // `rar` 7.23 clears file flag 0x0002 whenever it writes the record.
    *mtime = times.and_then(|t| t.mtime).map(|s| s.at).or(header_mtime);
    *out_header_mtime = header_mtime;
    // The attributes are the word's low 32 bits; a bit above them says
    // nothing. Measured against rar and unrar 7.23 for macOS, 10 Oct 2026
    // (`l` and `x` over each bit from 32 to 39, alone and beside a low
    // word). Read as all ones until then, which listed `ICADSHR` and gave
    // an extracted Unix file every permission.
    *out_attributes = (attributes & u64::from(u32::MAX)) as u32;
    *host_os = match host {
        0 => HostOs::Windows,
        1 => HostOs::Unix,
        n => HostOs::Other(u8::try_from(n).unwrap_or(u8::MAX)),
    };
    *out_checksum = checksum;
    *out_method = method;
    // RAR 5 packs the dictionary bits beside the method, so a STORED
    // member declares one too and reference `unrar lt` prints it
    // (`-m0 -md=128k`). A directory's bits name a size nothing decodes,
    // and the reference prints no `-md=` clause for one.
    *out_dictionary = dictionary.filter(|_| fflags & FF_DIRECTORY == 0);
    *out_method_code = method_code;
    *unpack_version = version;
    *rar4_salt = None;
    *out_crypt = crypt;
    *comment = None;
    *out_recovery_percent = recovery_percent;
    *out_version = file_version;
    // A file copy that names ITSELF can never be made (spec F 3.8.5): the
    // reference writes it as an empty file, and here it is corruption.
    if let Some(r) = redirect.as_mut() {
        if r.kind() == crate::read::RedirectionKind::FileCopy
            && head.get(r.target()) == head.get(name.clone())
        {
            r.fault = true;
        }
    }
    *out_redirect = redirect;
    // A header read although its records or its name do not fit it: its
    // checksum is right, so it is not reported as damaged, but nothing a
    // writer made holds these bytes. Its member is good only by its own
    // data checksum, and with none it fails (`FileHdr::unsound`): a
    // record lost behind the fault could have been the one that carries
    // the member's hash or says it is enciphered.
    if incoherent || !whole {
        out.mark_unsound();
    }
    let _ = data_start;
    Ok(name)
}

/// One redirection record's body (spec F 3.2.6.2), with `base` the offset
/// of the body within the header, so the target comes back as a span of
/// the header's bytes.
///
/// A record the engine cannot use is returned with `fault` set rather
/// than refused: a type that will not read, a target that runs past the
/// record, an empty target, a target holding a NUL byte. An UNKNOWN type
/// is not a fault (3.8.1): it is carried, and the caller declines it.
/// Bytes after the target are ignored, and so are flag bits other than
/// 0x0001.
pub(crate) fn parse_redirect(body: &[u8], base: usize) -> Redirect {
    use crate::read::RedirectionKind;
    let mut at = 0usize;
    let broken = |code| Redirect {
        code,
        dir: false,
        target_start: 0,
        target_len: 0,
        fault: true,
        in_content: false,
    };
    let Some(code) = vint::read(body, &mut at) else {
        return broken(0);
    };
    let kind = RedirectionKind::from_rar5(code);
    let known = !matches!(kind, RedirectionKind::Unknown(_));
    let Some(flags) = vint::read(body, &mut at) else {
        return Redirect {
            fault: known,
            ..broken(code)
        };
    };
    let target = vint::read_usize(body, &mut at)
        .and_then(|len| Some(at..at.checked_add(len)?))
        .filter(|span| span.end <= body.len());
    let Some(target) = target else {
        return Redirect {
            dir: flags & 1 != 0,
            fault: known,
            ..broken(code)
        };
    };
    let bytes = &body[target.clone()];
    Redirect {
        code,
        dir: flags & 1 != 0,
        target_start: (base + target.start) as u32,
        target_len: bytes.len() as u32,
        fault: known && (bytes.is_empty() || bytes.contains(&0)),
        in_content: false,
    }
}

fn take_u32(head: &[u8], at: &mut usize) -> Result<u32> {
    let bytes = head.get(*at..*at + 4).ok_or_else(corrupt)?;
    *at += 4;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// One entry of the quick open record (spec F 3.2.9.1). Used for one
/// thing: under `ReadOptions::read_damaged`, a sound entry stands in for
/// the header it copies where that header failed its own checksum
/// (`BlockReader::quick_open_copy`). A sound header is never read from
/// one (question 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `cached_size` is read by this package's tests alone.
#[allow(dead_code)]
pub(crate) struct QuickOpenEntry {
    /// Whether the entry's own CRC32 matched.
    pub checksum_ok: bool,
    /// Distance back from the QO service header to the cached header.
    pub distance_back: u64,
    /// The cached header's declared size.
    pub cached_size: u64,
}

/// Walk a quick open record's data area. Every entry must advance the walk,
/// so the count is bounded by the record's own size (spec F 4.3).
// Parsed and gone no further: spec F open question 4 rules that the
// quick-open record is exposed through `blocks()` and depended on by
// nothing. Only this package's tests read it today.
#[allow(dead_code)]
pub(crate) fn walk_quick_open(data: &[u8], mut each: impl FnMut(QuickOpenEntry)) -> Result<()> {
    let mut at = 0usize;
    while at < data.len() {
        let start = at;
        let stored = u32::from_le_bytes(
            data.get(at..at + 4)
                .ok_or_else(corrupt)?
                .try_into()
                .map_err(|_| corrupt())?,
        );
        at += 4;
        let size_at = at;
        let size = vint::read_usize(data, &mut at).ok_or_else(corrupt)?;
        let entry_end = at.checked_add(size).ok_or_else(corrupt)?;
        if entry_end > data.len() {
            return Err(corrupt());
        }
        let checksum_ok = crate::checksum::crc32(&data[size_at..entry_end]) == stored;
        let mut eat = at;
        let _flags = vint::read(data, &mut eat).ok_or_else(corrupt)?;
        let distance_back = vint::read(data, &mut eat).ok_or_else(corrupt)?;
        let cached_size = vint::read(data, &mut eat).ok_or_else(corrupt)?;
        each(QuickOpenEntry {
            checksum_ok,
            distance_back,
            cached_size,
        });
        at = entry_end;
        if at <= start {
            return Err(corrupt());
        }
    }
    Ok(())
}

/// The quick open entry that begins at `at` of the record's data area:
/// the entry, where its cached header lies in `data`, and where the next
/// entry begins. `None` at the end of the area and for an entry that
/// does not frame: every bound is checked before a byte is read through
/// it, and the next entry always begins after this one.
pub(crate) fn quick_open_entry(
    data: &[u8],
    at: usize,
) -> Option<(QuickOpenEntry, std::ops::Range<usize>, usize)> {
    let stored = u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?);
    let size_at = at + 4;
    let mut fields = size_at;
    let size = vint::read_usize(data, &mut fields)?;
    let entry_end = fields.checked_add(size).filter(|&end| end <= data.len())?;
    let entry = &data[..entry_end];
    let _flags = vint::read(entry, &mut fields)?;
    let distance_back = vint::read(entry, &mut fields)?;
    let cached_size = vint::read(entry, &mut fields)?;
    let cached_end = fields
        .checked_add(usize::try_from(cached_size).ok()?)
        .filter(|&end| end <= entry_end)?;
    Some((
        QuickOpenEntry {
            checksum_ok: crate::checksum::crc32(&data[size_at..entry_end]) == stored,
            distance_back,
            cached_size,
        },
        fields..cached_end,
        entry_end,
    ))
}

/// A FILE header's encryption record whose flag says a password check
/// record follows the IV while the record ends before those twelve bytes
/// do, with none of them or some: the record as it reads with NO check.
/// A damaged check record says nothing about the password and is absent
/// (SPEC-K 3.7.3 step 1), so the member is deciphered and its own data
/// checksum judges it; unrar 7.23 extracts such a member right, exit 0
/// (measured 9 Oct 2026). `None` for every other record, a version or an
/// exponent this engine does not know among them.
fn check_cut(body: &[u8]) -> Option<Rar5Record> {
    let mut at = 0;
    vint::read(body, &mut at)?;
    let flags_at = at;
    let flags = vint::read(body, &mut at)?;
    // The exponent, the salt and the IV.
    let fixed = at + 1 + 16 + 16;
    if flags & FLAG_CHECK == 0 || !(fixed..fixed + 12).contains(&body.len()) {
        return None;
    }
    // Two vints of at most ten bytes each stand before the fixed part.
    let mut plain = [0u8; 20 + 1 + 16 + 16];
    let plain = &mut plain[..fixed];
    plain.copy_from_slice(&body[..fixed]);
    plain[flags_at] &= !(FLAG_CHECK as u8);
    let mut record = Rar5Record::parse(plain, true).ok()?;
    record.flags = flags;
    Some(record)
}

/// The archive encryption header's own record (type 4), whose fields spec
/// K owns. Unlike the file encryption record it carries no initialisation
/// vector (spec K 3.7.1).
pub(crate) fn parse_archive_crypt(head: &[u8], common: &Common) -> Result<Rar5Record> {
    let body = head.get(common.at..common.head_len).ok_or_else(corrupt)?;
    Rar5Record::parse(body, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::block::FileHdr;

    /// A RAR 5 file header over `fflags`, `name` and `extra`, framed the
    /// way [`parse_common`] wants it: the CRC field, the size vint, then
    /// the block.
    fn file_header(fflags: u8, name: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut body = vec![TYPE_FILE as u8];
        let flags = if extra.is_empty() { 0 } else { HF_EXTRA as u8 };
        body.push(flags);
        if !extra.is_empty() {
            body.push(extra.len() as u8);
        }
        body.push(fflags);
        body.push(0x10); // the unpacked size
        body.push(0x20); // the attributes
        if u64::from(fflags) & MODIFICATION_TIME_PRESENT != 0 {
            body.extend_from_slice(&1_789_704_000u32.to_le_bytes());
        }
        if u64::from(fflags) & FF_CRC32 != 0 {
            body.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        }
        body.push(0x00); // the compression info: version 0, stored
        body.push(0x01); // the host, Unix
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        body.extend_from_slice(extra);
        let mut head = vec![0u8; 4];
        // Every size used here is under 128, so the vint is one byte.
        assert!(body.len() < 128, "the test builder writes a one byte vint");
        head.push(body.len() as u8);
        head.extend_from_slice(&body);
        head
    }

    /// One TIME extra record carrying a modification time in Unix seconds.
    fn time_record() -> Vec<u8> {
        let mut rec = vec![XF_TIME as u8, 0x03];
        rec.extend_from_slice(&1_789_704_000u32.to_le_bytes());
        let mut area = vec![rec.len() as u8];
        area.extend_from_slice(&rec);
        area
    }

    fn parse_into(head: &[u8], out: &mut FileHdr) {
        let common = parse_common(head).expect("the built header parses");
        parse_file_into(head, &common, 0, out).expect("the built header parses");
    }

    /// The parser fills a caller-owned slot, so a field it forgot to write
    /// would carry the PREVIOUS member's value into this one. The
    /// exhaustive destructuring in `parse_file_into` is what makes that a
    /// compile error; this test is the behavioural half, and it reads the
    /// fields a rich header sets and a plain one does not.
    #[test]
    fn a_reused_slot_carries_nothing_of_the_member_before_it() {
        let rich = file_header(
            (MODIFICATION_TIME_PRESENT | FF_CRC32 | FF_DIRECTORY) as u8,
            b"dir",
            &time_record(),
        );
        let plain = file_header(0, b"b", &[]);

        let mut reused = FileHdr::empty();
        parse_into(&rich, &mut reused);
        // The rich header really does set what the plain one clears,
        // without which the test below would pass on any parser at all.
        assert!(reused.is_directory, "the rich header is a directory");
        assert!(reused.mtime.is_some(), "the rich header carries a time");
        assert!(reused.checksum.is_some(), "the rich header carries a CRC");
        assert_eq!(reused.raw_checksum, 0xdead_beef);
        assert_eq!(reused.raw_name.end - reused.raw_name.start, 3);

        parse_into(&plain, &mut reused);
        let mut fresh = FileHdr::empty();
        parse_into(&plain, &mut fresh);

        assert!(!reused.is_directory, "the plain header is not a directory");
        assert_eq!(reused.mtime, fresh.mtime);
        assert_eq!(reused.header_mtime, fresh.header_mtime);
        assert_eq!(reused.checksum, fresh.checksum);
        assert_eq!(reused.raw_checksum, fresh.raw_checksum);
        assert_eq!(reused.raw_name, fresh.raw_name);
        assert_eq!(reused.file_flags, fresh.file_flags);
        assert_eq!(reused.unpacked_size, fresh.unpacked_size);
        assert_eq!(reused.dictionary, fresh.dictionary);
        assert_eq!(reused.host_raw, fresh.host_raw);
        assert_eq!(reused.host_os, fresh.host_os);
        assert_eq!(reused.method, fresh.method);
        assert_eq!(reused.is_directory, fresh.is_directory);
        assert_eq!(reused.service, fresh.service);
        assert_eq!(reused.recovery_percent, fresh.recovery_percent);
        assert_eq!(reused.redirect, fresh.redirect);
        assert!(reused.crypt.is_none() && fresh.crypt.is_none());
    }

    /// Spec F 3.2.6.2's record, OBSERVED bodies and the unusable rows.
    #[test]
    fn the_redirection_record_reads_as_spec_f_3_2_6_2_lists_it() {
        use crate::read::RedirectionKind;
        // The OBSERVED record bodies, and where their targets sit.
        let r = parse_redirect(&[0x01, 0x00, 0x05, b'a', b'.', b't', b'x', b't'], 100);
        assert_eq!(r.kind(), RedirectionKind::PosixSymlink);
        assert_eq!(
            (r.target_start, r.target_len, r.dir, r.fault),
            (103, 5, false, false)
        );
        let r = parse_redirect(&[0x01, 0x01, 0x01, b'd'], 0);
        assert!(r.dir && !r.fault);
        let r = parse_redirect(&[0x05, 0x00, 0x04, b'b', b'i', b'g', b'1'], 0);
        assert_eq!(r.kind(), RedirectionKind::FileCopy);
        // The unusable ones: a fault on a known kind, never on an unknown.
        assert!(parse_redirect(&[0x01, 0x00, 0x00], 0).fault);
        assert!(parse_redirect(&[0x01, 0x00, 0x09, b'a'], 0).fault);
        assert!(parse_redirect(&[0x01, 0x00, 0x03, b'a', 0, b'b'], 0).fault);
        assert!(parse_redirect(&[0x01], 0).fault);
        assert!(parse_redirect(&[], 0).fault);
        let r = parse_redirect(&[0x09, 0x00, 0x00], 0);
        assert_eq!((r.kind(), r.fault), (RedirectionKind::Unknown(9), false));
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
        // Two words of the target's own width: 16 bytes on a 64-bit
        // target and 8 on a 32-bit one.
        let word = std::mem::size_of::<usize>();
        assert_eq!(returned, 2 * word, "the name range is two words");
        // Non-vacuity: the bound above says something only because the
        // header it replaces is an order of magnitude larger.
        assert!(
            header >= 16 * returned,
            "the header is {header} bytes and the return is {returned}"
        );
    }
}
