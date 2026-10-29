//! DOS date and time, and the extended time area (spec F 3.3.8).
//!
//! A DOS time carries no zone, so it is read as UTC and the caller decides
//! what to do about that: this crate does no filesystem work and applies no
//! zone policy.

use crate::types::Timestamp;

/// Days from 1970-01-01 to `y-m-d` (proleptic Gregorian), by the shifted
/// era arithmetic: move the year start to March so the leap day lands at
/// the end of a 400-year era, count whole eras, then days within one.
const fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // 0..=399
    let mp = ((m + 9) % 12) as i64; // March = 0
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // 0..=365
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The fields a DOS time word holds, unvalidated.
pub(crate) const fn dos_parts(raw: u32) -> (i64, u32, u32, u32, u32, u32) {
    let date = raw >> 16;
    let time = raw & 0xFFFF;
    (
        1980 + ((date >> 9) & 0x7F) as i64,
        (date >> 5) & 0x0F,
        date & 0x1F,
        (time >> 11) & 0x1F,
        (time >> 5) & 0x3F,
        (time & 0x1F) * 2,
    )
}

/// A DOS date and time word as whole seconds. A word whose month or day is
/// zero (what a writer leaves for "no time") gives `None`; every other
/// value is converted, out-of-range fields and all, because a reader has no
/// business refusing a member over its clock.
pub(crate) fn from_dos(raw: u32) -> Option<Timestamp> {
    let (year, month, day, hour, minute, second) = dos_parts(raw);
    if month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(Timestamp {
        unix_seconds: days * 86_400
            + i64::from(hour) * 3600
            + i64::from(minute) * 60
            + i64::from(second),
        nanos: 0,
    })
}

/// Read the extended time area that file flag 0x1000 adds after the name
/// and salt, and return the modification time it refines. Only the
/// modification time reaches the API; the rest of the area is skipped.
///
/// The flags word gives each of modification, creation, access and archival
/// a 4-bit group, taken from the TOP nibble downwards: 0x8 the time is
/// present, 0x4 add one second to the DOS time, 0x3 the count of fraction
/// bytes that follow. The fraction is a counter of 100 ns units in three
/// bytes, least significant first; fewer than three present are its
/// high-order bytes.
pub(crate) fn read_extended(area: &[u8], dos: Option<Timestamp>) -> Option<Timestamp> {
    let flags = u16::from_le_bytes([*area.first()?, *area.get(1)?]);
    let mut at = 2usize;
    let mut mtime = dos;
    for slot in 0..4 {
        let group = (flags >> (12 - slot * 4)) & 0x0F;
        if slot > 0 {
            // The modification time is always present, in the DOS field;
            // the other three carry their own DOS word first.
            if group & 0x8 == 0 {
                continue;
            }
            at = at.checked_add(4)?;
        } else if group & 0x8 == 0 {
            continue;
        }
        let count = usize::from(group & 0x3);
        let bytes = area.get(at..at.checked_add(count)?)?;
        at += count;
        if slot != 0 {
            continue;
        }
        // Spec F 3.3.8 X2: the bytes present are the HIGH order ones of
        // the three, so the missing low ones count as zero.
        let mut ticks = 0u32;
        for (i, b) in bytes.iter().enumerate() {
            ticks |= u32::from(*b) << (8 * (3 - count + i));
        }
        let base = mtime?;
        // 100 ns units. Three bytes count up to 16,777,215 of them, which
        // is more than a second: the whole second is CARRIED, so `nanos`
        // keeps its documented range. Reference unrar 7.23 lists
        // `FF FF FF` on 00:00:00 as 00:00:01,677721500 (measured 4 Oct
        // 2026). At most three bytes, so the product fits.
        let nanos = (ticks & 0x00FF_FFFF) * 100;
        mtime = Some(Timestamp {
            unix_seconds: base.unix_seconds
                + i64::from(group & 0x4 != 0)
                + i64::from(nanos / 1_000_000_000),
            nanos: nanos % 1_000_000_000,
        });
    }
    mtime
}

/// The inverse of [`days_from_civil`]: the civil date `days` after
/// 1970-01-01.
const fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // 0..=399
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11, March = 0
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `unix_seconds` as a UTC calendar time: year, month, day, hour, minute,
/// second. Used by the block dump of spec F 5.2.
pub(crate) fn civil(unix_seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_seconds.div_euclid(86_400);
    let secs = unix_seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (secs / 3600) as u32,
        ((secs / 60) % 60) as u32,
        (secs % 60) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec F 5.3: DOS time `0x5D3286A0` is 2026-09-18 16:53:00.
    #[test]
    fn spec_f_5_3_dos_time() {
        let t = from_dos(0x5D32_86A0).unwrap();
        assert_eq!(dos_parts(0x5D32_86A0), (2026, 9, 18, 16, 53, 0));
        // 2026-09-18T16:53:00Z.
        assert_eq!(t.unix_seconds, 1_789_750_380);
        assert_eq!(t.nanos, 0);
    }

    #[test]
    fn civil_is_the_inverse_of_the_conversion() {
        for raw in [0x5D32_86A0u32, 0x2100_0000, 0x7FFF_FFFF, 0x0021_0000] {
            if let Some(t) = from_dos(raw) {
                let (y, m, d, hh, mm, ss) = civil(t.unix_seconds);
                let parts = dos_parts(raw);
                assert_eq!((y, m, d, hh, mm, ss), parts);
            }
        }
    }

    #[test]
    fn the_epoch_and_a_leap_day_convert() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
        assert_eq!(days_from_civil(1980, 1, 1), 3_652);
    }

    /// Spec F 5.3: flags 0xF000, DOS 06:54:42, fraction `73 6F 6B` gives
    /// 06:54:43 plus 704,088,300 ns.
    #[test]
    fn spec_f_5_3_extended_time() {
        // 2026-04-27 06:54:42.
        let dos = from_dos((((2026 - 1980) << 9 | 4 << 5 | 27) << 16) | (6 << 11 | 54 << 5 | 21));
        assert_eq!(dos_parts(0x5CBB_3756).0, 2026);
        let area = [0x00, 0xF0, 0x73, 0x6F, 0x6B];
        let t = read_extended(&area, dos).unwrap();
        assert_eq!(t.unix_seconds, dos.unwrap().unix_seconds + 1);
        assert_eq!(t.nanos, 704_088_300);
    }

    #[test]
    fn a_count_of_zero_adds_only_the_second() {
        let dos = from_dos(0x5D32_86A0);
        let t = read_extended(&[0x00, 0xC0], dos).unwrap();
        assert_eq!(t.unix_seconds, dos.unwrap().unix_seconds + 1);
        assert_eq!(t.nanos, 0);
    }

    #[test]
    fn a_short_area_costs_nothing() {
        assert_eq!(read_extended(&[], None), None);
        assert_eq!(read_extended(&[0x00], None), None);
        assert_eq!(read_extended(&[0x00, 0xF0], from_dos(0x5D32_86A0)), None);
    }
}
