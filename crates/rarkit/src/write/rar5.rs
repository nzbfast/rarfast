//! The RAR 5 block emitters (spec G sections 3.2 to 3.4, and 3.6 for the
//! reference layout's reserved widths).
//!
//! Every function here returns a COMPLETE block image - checksum, size
//! field, header - and never a data area and never the output. What a
//! block says is decided by its caller; what a block LOOKS like is
//! decided here, once, so that the two layouts differ only in the widths
//! they ask for.

use crate::carry::b_writers::rar50::write::reference::{
    vint_width, write_vint_padded, ARCHIVE_HAS_RECOVERY_RECORD, ARCHIVE_HAS_VOLUME_NUMBER,
    ARCHIVE_IS_VOLUME, BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME, BLOCK_CONTINUES_IN_NEXT_VOLUME,
    BLOCK_HAS_DATA_AREA, BLOCK_HAS_EXTRA_AREA, BLOCK_SKIP_IF_UNKNOWN, BLOCK_TYPE_END_OF_ARCHIVE,
    BLOCK_TYPE_FILE, BLOCK_TYPE_MAIN, BLOCK_TYPE_SERVICE, END_OF_ARCHIVE_NOT_LAST_VOLUME,
    FILETIME_UNIX_EPOCH, FILE_EXTRA_HASH, FILE_EXTRA_TIME, FILE_HAS_CRC32, FILE_HAS_UNIX_MTIME,
    FILE_IS_DIRECTORY, LOCATOR_HAS_QUICK_OPEN_OFFSET, LOCATOR_HAS_RECOVERY_RECORD_OFFSET,
    MAIN_EXTRA_LOCATOR, TIME_RECORD_HAS_MTIME, TIME_RECORD_UNIX_FORMAT,
    TIME_RECORD_UNIX_NANOSECONDS,
};
use crate::checksum::crc32;
use crate::types::Timestamp;
use crate::write::consts::*;
use crate::write::Digest;

/// Appends `value` as a shortest-form vint.
pub(crate) fn put_vint(out: &mut Vec<u8>, value: u64) {
    write_vint_padded(out, value, 1);
}

/// One extra-area record, APPENDED: its own length, its type, and its
/// body.
///
/// The length is worked out from `vint_width` rather than by building
/// the record's inside first, so that appending a record to an extra
/// area allocates nothing (spec G 7.3).
pub(crate) fn put_record(out: &mut Vec<u8>, kind: u64, body: &[u8]) {
    put_vint(out, (vint_width(kind) + body.len()) as u64);
    put_vint(out, kind);
    out.extend_from_slice(body);
}

/// One extra-area record as its own `Vec`, for the once-per-archive
/// blocks where a reused buffer would buy nothing.
pub(crate) fn record(kind: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    put_record(&mut out, kind, body);
    out
}

/// The buffers one header is built through, owned by the run and reused
/// by every member of it (spec G 7.3: no allocation per header).
#[derive(Default)]
pub(crate) struct Scratch {
    /// The extra area being accumulated.
    pub(crate) extra: Vec<u8>,
    /// The block-specific area, which in the RAR 4 family is the whole
    /// body.
    pub(crate) specific: Vec<u8>,
    /// One record's body, while it is being copied into `extra`.
    pub(crate) body: Vec<u8>,
    /// What [`frame_into`] lays the unframed header out in.
    pub(crate) header: Vec<u8>,
}

/// Frames a block: the header bytes, their length, and the CRC32 that
/// covers the length field TOGETHER with them (spec G 3.2).
///
/// `data` is the data area's length and the width to write it in; the
/// reference reserves a width wider than the value needs, and a reader
/// cannot tell the two apart.
pub(crate) fn frame(
    kind: u64,
    flags: u64,
    data: Option<(u64, usize)>,
    specific: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(specific.len() + extra.len() + 24);
    let mut scratch = Vec::with_capacity(specific.len() + extra.len() + 16);
    frame_into(&mut out, &mut scratch, kind, flags, data, specific, extra);
    out
}

/// [`frame`] into a caller's buffers: `out` is REPLACED by the framed
/// block and `scratch` holds the unframed header while its length is
/// measured. Neither is allocated here once it has grown.
///
/// The checksum still covers the length field together with the header,
/// which is why `out` carries four placeholder bytes that are filled in
/// last rather than a separate buffer being concatenated.
pub(crate) fn frame_into(
    out: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    kind: u64,
    flags: u64,
    data: Option<(u64, usize)>,
    specific: &[u8],
    extra: &[u8],
) {
    let mut flags = flags;
    if !extra.is_empty() {
        flags |= BLOCK_HAS_EXTRA_AREA;
    }
    if data.is_some() {
        flags |= BLOCK_HAS_DATA_AREA;
    }
    scratch.clear();
    put_vint(scratch, kind);
    put_vint(scratch, flags);
    if !extra.is_empty() {
        put_vint(scratch, extra.len() as u64);
    }
    if let Some((size, width)) = data {
        write_vint_padded(scratch, size, width);
    }
    scratch.extend_from_slice(specific);
    scratch.extend_from_slice(extra);

    out.clear();
    out.extend_from_slice(&[0; 4]);
    put_vint(out, scratch.len() as u64);
    out.extend_from_slice(scratch);
    let checksum = crc32(&out[4..]);
    out[..4].copy_from_slice(&checksum.to_le_bytes());
}

/// How wide a size field is written.
///
/// The default layout writes what the value needs. The reference lays a
/// header out before it has streamed the member, so it reserves a wider
/// field and pads it (spec G 3.6.4); the widths are measured, and
/// `vectors-G/widths.tsv` is the measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reserve {
    /// Shortest form everywhere: nothing is reserved and nothing is patched.
    Natural,
    /// The reference's reserved widths for a member it is about to stream.
    Reference,
}

impl Reserve {
    /// The width of a member's packed and unpacked size fields.
    pub(crate) fn size_width(self, size: u64, is_directory: bool) -> usize {
        match self {
            Reserve::Natural => vint_width(size),
            Reserve::Reference if is_directory => 1,
            Reserve::Reference => {
                // The width of 2 * size + 1024, and one byte more in each
                // of the two bands above 1 MiB. The first two crossings
                // follow from the formula and were then found by
                // bisection; the two steps are measured only.
                let mut width = vint_width(2u64.saturating_mul(size).saturating_add(1024));
                if size >= 1 << 20 {
                    width += 1;
                }
                if size >= 1 << 23 {
                    width += 1;
                }
                width
            }
        }
    }

    /// The width of the compression information field.
    pub(crate) fn compression_width(self) -> usize {
        match self {
            Reserve::Natural => 1,
            Reserve::Reference => 2,
        }
    }
}

/// The width the reference reserves for each offset of the locator
/// (spec G 3.6.3): the vint width of 4,096 times one more than the sum,
/// over the members, of the data length, 32, and three for each CHARACTER
/// of the name. `members` is one (data length, name) pair a member, a
/// directory with no data; service blocks are not members and add
/// nothing.
///
/// A character is a Unicode code point, so of a UTF-8 name every byte
/// that is not a continuation byte, which is also an answer for a name
/// that is not UTF-8 at all.
pub(crate) fn locator_reserve_width<'n>(members: impl Iterator<Item = (u64, &'n [u8])>) -> usize {
    let characters = |name: &[u8]| name.iter().filter(|byte| **byte & 0xC0 != 0x80).count() as u64;
    let sum = members.fold(1u64, |sum, (data_len, name)| {
        sum.saturating_add(data_len)
            .saturating_add(32)
            .saturating_add(3 * characters(name))
    });
    vint_width(sum.saturating_mul(1 << 12))
}

/// What the main header says (spec G 3.3.2).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MainPlan {
    /// This archive is one volume of a set.
    pub(crate) volume_set: bool,
    /// The volume's zero-based number; the first volume writes no field.
    pub(crate) volume_number: u32,
    /// The members are one solid group.
    pub(crate) solid: bool,
    /// This volume carries an inline recovery record.
    pub(crate) recovery: bool,
    /// The archive is locked.
    pub(crate) locked: bool,
    /// The locator record to carry, if any.
    pub(crate) locator: Option<Locator>,
}

/// The locator record's two offsets, each counted from the first byte
/// after the signature, and the width each is written in.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Locator {
    /// The quick-open service block's offset, and its reserved width.
    pub(crate) quick_open: Option<(u64, usize)>,
    /// The recovery record block's offset, and its reserved width.
    pub(crate) recovery: Option<(u64, usize)>,
}

/// The width a vint of `value` takes, which a rewrite needs to reserve a
/// locator offset before it knows the offset (`edit::rewrite`).
pub(crate) fn vint_width_of(value: u64) -> usize {
    vint_width(value)
}

/// The main archive header.
pub(crate) fn main_header(plan: &MainPlan) -> Vec<u8> {
    let mut archive_flags = 0u64;
    if plan.volume_set {
        archive_flags |= ARCHIVE_IS_VOLUME;
    }
    if plan.volume_set && plan.volume_number != 0 {
        archive_flags |= ARCHIVE_HAS_VOLUME_NUMBER;
    }
    if plan.solid {
        archive_flags |= ARCHIVE_IS_SOLID;
    }
    if plan.recovery {
        archive_flags |= ARCHIVE_HAS_RECOVERY_RECORD;
    }
    if plan.locked {
        archive_flags |= ARCHIVE_IS_LOCKED;
    }

    let mut specific = Vec::with_capacity(8);
    put_vint(&mut specific, archive_flags);
    if archive_flags & ARCHIVE_HAS_VOLUME_NUMBER != 0 {
        put_vint(&mut specific, u64::from(plan.volume_number));
    }

    let extra = match plan.locator {
        None => Vec::new(),
        Some(locator) => {
            let mut flags = 0u64;
            if locator.quick_open.is_some() {
                flags |= LOCATOR_HAS_QUICK_OPEN_OFFSET;
            }
            if locator.recovery.is_some() {
                flags |= LOCATOR_HAS_RECOVERY_RECORD_OFFSET;
            }
            let mut body = Vec::with_capacity(12);
            put_vint(&mut body, flags);
            // In flag order, which is the order a reader takes them in.
            for field in [locator.quick_open, locator.recovery].into_iter().flatten() {
                write_vint_padded(&mut body, field.0, field.1);
            }
            record(MAIN_EXTRA_LOCATOR, &body)
        }
    };

    frame(
        BLOCK_TYPE_MAIN,
        BLOCK_SKIP_IF_UNKNOWN,
        None,
        &specific,
        &extra,
    )
}

/// Where a fragment sits in a member split across volumes (spec G 3.10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Fragment {
    /// The member is not split.
    #[default]
    Whole,
    /// The first fragment of a split member.
    First,
    /// Neither the first fragment nor the last.
    Middle,
    /// The last fragment of a split member.
    Last,
}

impl Fragment {
    /// This fragment continues a member from the previous volume.
    pub(crate) fn continued(self) -> bool {
        matches!(self, Fragment::Middle | Fragment::Last)
    }

    /// This fragment continues into the next volume.
    pub(crate) fn continues(self) -> bool {
        matches!(self, Fragment::First | Fragment::Middle)
    }
}

/// The compression information field's four values (spec G 3.4.1).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Compression {
    /// 0 stored, 1 fastest to 5 best.
    pub(crate) method: u8,
    /// The dictionary as `128 KiB << power`.
    pub(crate) power: u32,
    /// This member continues the previous member's history.
    pub(crate) solid: bool,
}

impl Compression {
    /// The field's value.
    pub(crate) fn word(self) -> u64 {
        let mut word = u64::from(COMPRESSION_VERSION_BITS);
        if self.solid {
            word |= COMPRESSION_SOLID_BIT;
        }
        word |= u64::from(self.method) << COMPRESSION_METHOD_SHIFT;
        word |= u64::from(self.power) << COMPRESSION_DICTIONARY_SHIFT;
        word
    }
}

/// What one file or service header says (spec G 3.3.3).
pub(crate) struct FilePlan<'a> {
    /// The name as stored: UTF-8, `/` separated.
    pub(crate) name: &'a [u8],
    /// The whole member's size, on every fragment.
    pub(crate) unpacked_size: u64,
    /// This fragment's stored length.
    pub(crate) packed_size: u64,
    /// The attribute word, uninterpreted.
    pub(crate) attributes: u64,
    /// 0 Windows, 1 Unix.
    pub(crate) host_os: u64,
    /// Whether this entry is a directory.
    pub(crate) is_directory: bool,
    /// The modification time, or none.
    pub(crate) mtime: Option<Timestamp>,
    /// The payload's checksum, or none for a directory.
    pub(crate) digest: Option<Digest>,
    /// The compression information.
    pub(crate) compression: Compression,
    /// Where this fragment sits.
    pub(crate) fragment: Fragment,
    /// Which widths to write.
    pub(crate) reserve: Reserve,
    /// The width the PACKED size field is reserved at, overriding
    /// [`Reserve`], or none for whatever the value needs.
    ///
    /// This is spec G 3.5's one exception to minimum-width vints, decided on
    /// 19 Sep 2026, extended on 20 Sep and narrowed the same day: a
    /// member of a solid run in a volume set, or a member of a non-solid
    /// volume set larger than one window that the write is STREAMING
    /// under a memory ceiling the caller set, in the DEFAULT layout, and
    /// nothing else. `Run::packed_reserve`
    /// decides which members those are and works the width out; this
    /// field is only how the width reaches the emitter. A width smaller
    /// than the value needs is not honoured - the field is widened to the
    /// value - because 3.5 forbids emitting a field that could not be
    /// patched to the true packed size.
    pub(crate) packed_reserve: Option<usize>,
    /// The encryption record (spec K 3.5), already built, or none.
    pub(crate) encryption: Option<&'a [u8]>,
    /// A service block's own parameter record body, or none.
    pub(crate) service_data: Option<u64>,
    /// Whether this is a service header rather than a file header.
    pub(crate) service: bool,
}

/// A file header, or a service header, which is the same layout under a
/// different block type (spec G 3.3.3).
/// A file header, or a service header, built into `out` through
/// `scratch`. `out` is REPLACED by the header image.
///
/// Every buffer this needs comes from `scratch`, so a run that writes a
/// thousand members allocates for the first header and for none of the
/// rest (spec G 7.3). The two small fixed-width fields are arrays on the
/// stack rather than buffers, because they are four bytes each.
pub(crate) fn file_header_into(plan: &FilePlan<'_>, scratch: &mut Scratch, out: &mut Vec<u8>) {
    let Scratch {
        extra,
        specific,
        body,
        header,
    } = scratch;
    let mut file_flags = 0u64;
    extra.clear();
    specific.clear();

    if let Some(encryption) = plan.encryption {
        put_record(extra, FILE_EXTRA_ENCRYPTION, encryption);
    }

    if plan.is_directory {
        file_flags |= FILE_IS_DIRECTORY;
    }

    // The header's own CRC32 field, or a hash record instead of it: never
    // both (spec G 3.3.3).
    let mut crc_field = None;
    match plan.digest {
        None => {}
        Some(Digest::Crc32(value)) => {
            file_flags |= FILE_HAS_CRC32;
            crc_field = Some(value.to_le_bytes());
        }
        Some(Digest::Blake2sp(bytes)) => {
            body.clear();
            body.push(0); // hash type 0: BLAKE2sp
            body.extend_from_slice(&bytes);
            put_record(extra, FILE_EXTRA_HASH, body);
        }
    }

    let mut mtime_field = None;
    if let Some(time) = plan.mtime {
        body.clear();
        match time_placement(time, plan.host_os, plan.reserve, body) {
            Some(seconds) => {
                file_flags |= FILE_HAS_UNIX_MTIME;
                mtime_field = Some(seconds.to_le_bytes());
            }
            None => put_record(extra, FILE_EXTRA_TIME, body),
        }
    }

    if let Some(value) = plan.service_data {
        body.clear();
        put_vint(body, value);
        put_record(extra, FILE_EXTRA_SERVICE_DATA, body);
    }

    let size_width = plan
        .reserve
        .size_width(plan.unpacked_size, plan.is_directory);
    put_vint(specific, file_flags);
    write_vint_padded(specific, plan.unpacked_size, size_width);
    put_vint(specific, plan.attributes);
    if let Some(field) = mtime_field {
        specific.extend_from_slice(&field);
    }
    if let Some(field) = crc_field {
        specific.extend_from_slice(&field);
    }
    write_vint_padded(
        specific,
        plan.compression.word(),
        plan.reserve.compression_width(),
    );
    put_vint(specific, plan.host_os);
    put_vint(specific, plan.name.len() as u64);
    specific.extend_from_slice(plan.name);

    let mut block_flags = 0u64;
    if plan.service {
        block_flags |= BLOCK_SKIP_IF_UNKNOWN;
    }
    if plan.fragment.continued() {
        block_flags |= BLOCK_CONTINUED_FROM_PREVIOUS_VOLUME;
    }
    if plan.fragment.continues() {
        block_flags |= BLOCK_CONTINUES_IN_NEXT_VOLUME;
    }

    let kind = if plan.service {
        BLOCK_TYPE_SERVICE
    } else {
        BLOCK_TYPE_FILE
    };
    let data_width = match plan.packed_reserve {
        Some(width) => width.max(vint_width(plan.packed_size)),
        None => plan.reserve.size_width(plan.packed_size, plan.is_directory),
    };
    frame_into(
        out,
        header,
        kind,
        block_flags,
        Some((plan.packed_size, data_width)),
        specific,
        extra,
    );
}

/// Spec G 3.4.2: whole seconds go in the header's own field, a fraction
/// goes in a record, and a Windows-host member always uses a record
/// because the header field is Unix seconds by definition.
///
/// `Some(seconds)` is the header's own 4 byte field and `body` is
/// untouched; `None` means the record's body has been APPENDED to
/// `body`, which the caller hands to [`put_record`].
fn time_placement(
    time: Timestamp,
    host_os: u64,
    reserve: Reserve,
    body: &mut Vec<u8>,
) -> Option<u32> {
    let windows_host = host_os == HOST_OS_WINDOWS_BYTE;
    // **A time the 32 bit Unix field cannot say goes in the record's 64
    // bit form, on either host**, where it is exact from 1601 on (spec G
    // section 4: stated exactly, never silently wrong). The Unix forms
    // would have to clamp it to 1970 or 2106.
    let in_unix_field = u32::try_from(time.unix_seconds).is_ok();
    if !windows_host && in_unix_field && time.nanos == 0 {
        return Some(clamp_unix_seconds(time.unix_seconds));
    }
    if windows_host || !in_unix_field {
        put_vint(body, TIME_RECORD_HAS_MTIME);
        body.extend_from_slice(&filetime(time).to_le_bytes());
    } else {
        let mut flags = TIME_RECORD_UNIX_FORMAT | TIME_RECORD_HAS_MTIME;
        if time.nanos != 0 {
            flags |= TIME_RECORD_UNIX_NANOSECONDS;
        }
        put_vint(body, flags);
        body.extend_from_slice(&clamp_unix_seconds(time.unix_seconds).to_le_bytes());
        if time.nanos != 0 {
            body.extend_from_slice(&time.nanos.to_le_bytes());
        }
    }
    None
}

/// The RAR 5 host byte of a Windows member.
pub(crate) const HOST_OS_WINDOWS_BYTE: u64 = 0;
/// The RAR 5 host byte of a Unix member.
// The other half of the pair spec G 3.4.3 names; the code tests for
// the Windows byte alone.
#[allow(dead_code)]
pub(crate) const HOST_OS_UNIX_BYTE: u64 = 1;

/// A Unix time in the 32 bit field the header carries, saturating rather
/// than wrapping: a time outside the field's range is clamped and never
/// silently becomes a different time in range (spec G section 4).
fn clamp_unix_seconds(seconds: i64) -> u32 {
    seconds.clamp(0, i64::from(u32::MAX)) as u32
}

/// A Unix time as a Windows FILETIME: 100 nanosecond ticks from 1601.
///
/// A time before 1970 is a FILETIME like any other, down to 1601, and is
/// written as one; it used to be raised to 1970. Only a time outside what
/// the field can say at all, before 1601 or past its 64 bits, saturates.
fn filetime(time: Timestamp) -> u64 {
    let ticks = i128::from(FILETIME_UNIX_EPOCH)
        + i128::from(time.unix_seconds) * 10_000_000
        + i128::from(time.nanos / 100);
    ticks.clamp(0, i128::from(u64::MAX)) as u64
}

/// A service header (spec G 3.3.4). The caller writes the returned header
/// and then the data area it describes.
///
/// A service block's size fields take a FIXED two-byte width in the
/// reference layout, as the reference writes them, and the shortest form
/// in the default layout. `skip_if_unknown` is measured per service and
/// is not the same for all of them: the quick-open block sets it and the
/// comment block does not.
pub(crate) fn service_header(
    name: &[u8],
    data_len: u64,
    checksum: Option<u32>,
    host_os: u64,
    skip_if_unknown: bool,
    parameter: Option<u64>,
    reserve: Reserve,
) -> Vec<u8> {
    let width = match reserve {
        Reserve::Natural => vint_width(data_len),
        Reserve::Reference => SERVICE_SIZE_WIDTH,
    };
    let compression_width = match reserve {
        Reserve::Natural => 1,
        Reserve::Reference => 2,
    };

    let mut extra = Vec::new();
    if let Some(value) = parameter {
        let mut body = Vec::new();
        put_vint(&mut body, value);
        extra.extend_from_slice(&record(FILE_EXTRA_SERVICE_DATA, &body));
    }

    let mut specific = Vec::with_capacity(name.len() + 24);
    put_vint(
        &mut specific,
        if checksum.is_some() {
            FILE_HAS_CRC32
        } else {
            0
        },
    );
    write_vint_padded(&mut specific, data_len, width);
    put_vint(&mut specific, 0); // attributes
    if let Some(value) = checksum {
        specific.extend_from_slice(&value.to_le_bytes());
    }
    write_vint_padded(&mut specific, 0, compression_width);
    put_vint(&mut specific, host_os);
    put_vint(&mut specific, name.len() as u64);
    specific.extend_from_slice(name);

    let flags = if skip_if_unknown {
        BLOCK_SKIP_IF_UNKNOWN
    } else {
        0
    };
    frame(
        BLOCK_TYPE_SERVICE,
        flags,
        Some((data_len, width)),
        &specific,
        &extra,
    )
}

/// The width a service block's two size fields take in the reference
/// layout, measured: two bytes, padded. It is load bearing for the
/// quick-open block, whose index can pass 16,383 bytes (about 190 cached
/// headers): written into a one-byte field the length truncates, and the
/// reference then reports a corrupt header on every command but `l`.
pub(crate) const SERVICE_SIZE_WIDTH: usize = 2;

/// The end of archive header (spec G 3.3.5).
pub(crate) fn end_header(next_volume: bool) -> Vec<u8> {
    let mut specific = Vec::with_capacity(1);
    put_vint(
        &mut specific,
        if next_volume {
            END_OF_ARCHIVE_NOT_LAST_VOLUME
        } else {
            0
        },
    );
    frame(
        BLOCK_TYPE_END_OF_ARCHIVE,
        BLOCK_SKIP_IF_UNKNOWN,
        None,
        &specific,
        &[],
    )
}

/// One entry of the quick-open index (spec G 3.6.6): a cached copy of a
/// member's header, with the distance back to where that header sits.
pub(crate) fn quick_open_entry(distance_back: u64, header: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(header.len() + 8);
    put_vint(&mut body, 0);
    put_vint(&mut body, distance_back);
    put_vint(&mut body, header.len() as u64);
    body.extend_from_slice(header);

    let mut sized = Vec::with_capacity(body.len() + 4);
    put_vint(&mut sized, body.len() as u64);
    sized.extend_from_slice(&body);

    let mut out = Vec::with_capacity(sized.len() + 4);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out
}

/// The length [`quick_open_entry`] gives for a header of `header_len`
/// bytes `distance_back` from the block, without building it.
pub(crate) fn quick_open_entry_len(distance_back: u64, header_len: usize) -> u64 {
    let body = 1 + vint_width(distance_back) + vint_width(header_len as u64) + header_len;
    (4 + vint_width(body as u64) + body) as u64
}

/// The quick-open service header, for an index of `data`.
pub(crate) fn quick_open_header(data_len: u64, host_os: u64) -> Vec<u8> {
    service_header(
        SERVICE_QUICK_OPEN,
        data_len,
        None,
        host_os,
        true,
        None,
        Reserve::Reference,
    )
}
