//! The RAR 5 `.rev` file's layout (spec L 3.6.1).
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 8 | `Rar!` 0x1A `Rev` |
//! | 8 | 4 | CRC32 of bytes 12 to `16 + hsize` |
//! | 12 | 4 | `hsize`: `11 + 12 k` as written, up to 1,048,576 as read |
//! | 16 | 1 | version, 1 |
//! | 17 | 2 | `k`, data volume count |
//! | 19 | 2 | `m`, recovery volume count |
//! | 21 | 2 | number, `k + i` for recovery row `i` |
//! | 23 | 4 | CRC32 of the payload |
//! | 27 | 12 k | per data volume: size (u64), CRC32 (u32) |
//! | 16 + hsize | L | the payload: recovery row `i` |
//!
//! `L` is the largest data volume's size rounded up to even; data volume
//! `j`, zero-padded to `L`, is data shard `j`.

use crate::checksum::crc32;
use crate::recovery::io::{length, read_exact_at};
use crate::rev5::{DataVolume, RevInfo};
use crate::source::RangeSource;
use crate::{Error, ErrorKind, RecoveryFailure, Result};

/// The eight signature bytes.
pub(crate) const SIGNATURE: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x52, 0x65, 0x76];
/// Bytes before the header body.
const BODY_AT: usize = 16;
/// The header body with an empty table.
const BODY_FIXED: u32 = 11;
/// Bytes per table row.
const TABLE_ROW: usize = 12;
/// The version byte this crate reads and writes.
const VERSION: u8 = 1;
/// The longest header that is used (spec L 3.6.2). Observed, not chosen:
/// the reference rebuilds from a header of 1,048,576 bytes and passes
/// over one of 1,048,577.
const HEADER_AT_MOST: u32 = 1_048_576;
/// Section 4's ceiling on a declared data volume size.
const MAX_VOLUME: u64 = 1 << 56;

/// `hsize` for `k` data volumes.
pub(crate) fn header_size(k: u16) -> u32 {
    BODY_FIXED + TABLE_ROW as u32 * u32::from(k)
}

/// The payload length for a set whose largest volume is `max_size`.
pub(crate) fn payload_len(max_size: u64) -> u64 {
    max_size + (max_size % 2)
}

fn damaged() -> Error {
    Error::new(ErrorKind::Recovery(RecoveryFailure::RecoveryDamaged))
}

/// A little endian field of the file's first 27 bytes.
fn lead_u16(lead: &[u8; 27], at: usize) -> u16 {
    u16::from_le_bytes([lead[at], lead[at + 1]])
}

/// See [`lead_u16`].
fn lead_u32(lead: &[u8; 27], at: usize) -> u32 {
    u32::from_le_bytes([lead[at], lead[at + 1], lead[at + 2], lead[at + 3]])
}

/// Read one recovery volume's header and say whether the file is valid
/// (spec L 3.6.2): every condition of that list but the payload's own
/// CRC32, which is [`RevInfo::verify_payload`]'s to check.
///
/// Everything the header's length depends on is in the first 27 bytes,
/// so the length is bounded before a byte of the rest is read or a byte
/// of memory asked for it. A header may be longer than its table: the
/// bytes between the table's end and `16 + hsize` are under the header
/// CRC32 and mean nothing else.
pub(crate) fn parse(src: &dyn RangeSource) -> Result<RevInfo> {
    let mut lead = [0u8; 27];
    read_exact_at(src, 0, &mut lead)?;
    if lead[..8] != SIGNATURE {
        return Err(Error::new(ErrorKind::NotAnArchive));
    }
    let hsize = lead_u32(&lead, 12);
    let k = lead_u16(&lead, 17);
    let volumes = u32::from(k) + u32::from(lead_u16(&lead, 19));
    let number = u32::from(lead_u16(&lead, 21));
    let table_end = header_size(k);
    let valid = lead[BODY_AT] == VERSION
        && k >= 1
        && volumes > u32::from(k)
        && volumes <= 65_535
        && (u32::from(k)..volumes).contains(&number)
        && (table_end..=HEADER_AT_MOST).contains(&hsize);
    if !valid {
        return Err(damaged());
    }

    // The header from its version byte to its end, table and any filler.
    let mut body = vec![0u8; hsize as usize];
    read_exact_at(src, BODY_AT as u64, &mut body)?;
    let mut header_crc = crc32fast::Hasher::new();
    header_crc.update(&lead[12..BODY_AT]);
    header_crc.update(&body);
    if header_crc.finalize() != lead_u32(&lead, 8) {
        return Err(damaged());
    }

    let table = &body[BODY_FIXED as usize..table_end as usize];
    let mut data_volumes = Vec::with_capacity(usize::from(k));
    for row in table.as_chunks::<TABLE_ROW>().0 {
        let (size, crc) = row.split_at(8);
        let volume = DataVolume {
            size: u64::from_le_bytes(size.try_into().expect("eight")),
            crc32: u32::from_le_bytes(crc.try_into().expect("four")),
        };
        if volume.size > MAX_VOLUME {
            return Err(damaged());
        }
        data_volumes.push(volume);
    }
    let largest = data_volumes.iter().map(|volume| volume.size).max();
    let payload_at = BODY_AT as u64 + u64::from(hsize);
    let payload_end = payload_at + payload_len(largest.unwrap_or(0));
    // Stricter than the reference, and kept: the payload is exactly the
    // length its own table gives.
    if length(src) != payload_end {
        return Err(damaged());
    }
    Ok(RevInfo {
        row: number - u32::from(k),
        data_count: u32::from(k),
        recovery_count: volumes - u32::from(k),
        data_volumes,
        payload: payload_at..payload_end,
        payload_crc: lead_u32(&lead, 23),
    })
}

/// Build the header bytes of recovery row `row`.
pub(crate) fn header(table: &[DataVolume], m: u16, row: u16, payload_crc: u32) -> Vec<u8> {
    let k = table.len() as u16;
    let hsize = header_size(k);
    let mut out = vec![0u8; BODY_AT + hsize as usize];
    out[..8].copy_from_slice(&SIGNATURE);
    out[12..16].copy_from_slice(&hsize.to_le_bytes());
    out[BODY_AT] = VERSION;
    out[17..19].copy_from_slice(&k.to_le_bytes());
    out[19..21].copy_from_slice(&m.to_le_bytes());
    out[21..23].copy_from_slice(&(k + row).to_le_bytes());
    out[23..27].copy_from_slice(&payload_crc.to_le_bytes());
    let (slots, _) = out[27..].as_chunks_mut::<TABLE_ROW>();
    for (slot, volume) in slots.iter_mut().zip(table) {
        slot[..8].copy_from_slice(&volume.size.to_le_bytes());
        slot[8..12].copy_from_slice(&volume.crc32.to_le_bytes());
    }
    let crc = crc32(&out[12..]);
    out[8..12].copy_from_slice(&crc.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sound `.rev` file of `k` data volumes of four bytes each, row 0
    /// of `m`, whose header declares `hsize` bytes: the table, then
    /// filler up to `hsize`, the header CRC32 over all of it, then the
    /// four byte payload.
    fn rev_file(k: u16, m: u16, hsize: u32) -> Vec<u8> {
        let table = vec![
            DataVolume {
                size: 4,
                crc32: 0x1357_9bdf,
            };
            usize::from(k)
        ];
        let payload = [9u8, 8, 7, 6];
        let mut out = header(&table, m, 0, crc32(&payload));
        out.resize(BODY_AT + hsize as usize, 0xA5);
        out[12..16].copy_from_slice(&hsize.to_le_bytes());
        let crc = crc32(&out[12..]);
        out[8..12].copy_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn is_damaged(outcome: Result<RevInfo>) -> bool {
        matches!(
            outcome.as_ref().map_err(|err| err.kind()),
            Err(ErrorKind::Recovery(RecoveryFailure::RecoveryDamaged))
        )
    }

    /// Spec L 3.6.2: a header LONGER than its table is used, up to
    /// 1,048,576 bytes, the bytes after the table covered by the header
    /// CRC32 and otherwise ignored; one byte shorter than the table, or
    /// one byte past 1,048,576, and the file is not valid. The header
    /// sizes are the probe's for `k = 3`, and both edges.
    /// Single threaded; about 1 MiB a file.
    #[test]
    fn a_header_longer_than_its_table_is_used_up_to_a_mebibyte() {
        let k = 3u16;
        let table_end = header_size(k);
        assert_eq!(table_end, 47);
        for hsize in [47u32, 48, 59, 65_536, 1_048_576] {
            let file = rev_file(k, 2, hsize);
            let info = parse(&file).unwrap_or_else(|err| panic!("hsize {hsize}: {err:?}"));
            assert_eq!((info.data_count, info.recovery_count, info.row), (3, 2, 0));
            assert_eq!(
                info.data_volumes.len(),
                3,
                "hsize {hsize}: the table is k rows"
            );
            let payload_at = 16 + u64::from(hsize);
            assert_eq!(info.payload, payload_at..payload_at + 4, "hsize {hsize}");
        }
        for hsize in [46u32, 1_048_577] {
            assert!(is_damaged(parse(&rev_file(k, 2, hsize))), "hsize {hsize}");
        }
        // A byte of the filler is under the header CRC32 like any other.
        let mut file = rev_file(k, 2, 59);
        file[16 + 50] ^= 1;
        assert!(is_damaged(parse(&file)));
    }

    /// Spec L 3.6.2 and section 4, each edge the reference shows: the
    /// counts, their sum, the row number and the version.
    #[test]
    fn the_counts_the_number_and_the_version_at_their_edges() {
        let good = rev_file(3, 2, 47);
        assert!(parse(&good).is_ok());
        let with = |at: usize, value: u16| {
            let mut file = good.clone();
            file[at..at + 2].copy_from_slice(&value.to_le_bytes());
            let crc = crc32(&file[12..16 + 47]);
            file[8..12].copy_from_slice(&crc.to_le_bytes());
            parse(&file)
        };
        // `m` at 19: with `k = 3`, 65,532 is the most.
        assert!(with(19, 65_532).is_ok());
        assert!(is_damaged(with(19, 65_533)));
        assert!(is_damaged(with(19, 0)));
        // The number at 21: `k <= number < k + m`.
        assert!(is_damaged(with(21, 2)));
        assert!(with(21, 4).is_ok());
        assert!(is_damaged(with(21, 5)));
        // The version at 16.
        for version in [0u8, 2] {
            let mut file = good.clone();
            file[16] = version;
            let crc = crc32(&file[12..16 + 47]);
            file[8..12].copy_from_slice(&crc.to_le_bytes());
            assert!(is_damaged(parse(&file)), "version {version}");
        }
        // Where this reader is stricter than the reference and stays so:
        // the payload is exactly the table's length, not a byte more.
        let mut longer = good.clone();
        longer.push(0);
        assert!(is_damaged(parse(&longer)));
    }
}
