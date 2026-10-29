//! The RAR 5 extra TIME record, type 3 (spec F 3.2.6.1).
//!
//! A member whose modification time has a sub-second part does NOT carry
//! that time in the file header's own mtime field: file flag 0x0002 is
//! clear and the time lives here instead, which is what every archive
//! `rar` 7.23 writes from a freshly created file looks like. A reader that
//! knows only the header field therefore has no date at all for such a
//! member.
//!
//! Nothing here fails. A record too short for the times its flags declare,
//! a flag bit this package does not know, and trailing bytes inside a
//! complete record are all accepted, because reference unrar 7.23 accepts
//! all three (3.2.6.1). A field that runs past the record's own size is
//! ABSENT, never zero: a member with no modification time reports none,
//! and it is the caller's listing that prints the reference's question
//! marks.

use crate::types::Timestamp;

/// Record flags (spec F 3.2.6.1).
const TF_UNIX: u64 = 0x0001;
const TF_MTIME: u64 = 0x0002;
const TF_CTIME: u64 = 0x0004;
const TF_ATIME: u64 = 0x0008;
const TF_NANO: u64 = 0x0010;

/// Seconds from 1601-01-01 to 1970-01-01, which is what a Windows FILETIME
/// counts from and a unix time does not.
const FILETIME_EPOCH_OFFSET: i64 = 11_644_473_600;

/// Ticks of 100 ns in one second, the unit a FILETIME is kept in.
const FILETIME_TICKS_PER_SECOND: i64 = 10_000_000;

/// One time the record carried, with the stored form kept beside the
/// converted one so the block walk of 5.2 can print what the bytes said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    /// The time as this crate carries times everywhere else.
    pub at: Timestamp,
    /// The stored figure: the unix seconds count in the UNIX form, the
    /// whole FILETIME in the WINDOWS form.
    pub raw: u64,
    /// The stored nanosecond field, which is the UNIX form's separate
    /// `u32` or the sub-second part the FILETIME already carries. Kept
    /// unclamped, so a field above 999,999,999 is reported as it was
    /// stored; `Stamp::at` holds zero for one of those rather than break
    /// [`Timestamp`]'s own range.
    pub raw_nanos: u32,
}

/// What one extra TIME record carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Times {
    /// The record's flags word, as stored, unknown bits included.
    pub flags: u64,
    /// Whether the times are in the UNIX form (flag 0x0001). The form is
    /// the RECORD's and has nothing to do with the header's host OS, which
    /// `f19_htime_win.rar` proves by carrying the WINDOWS form under host
    /// OS 1.
    pub unix_form: bool,
    /// The modification time, `None` when the record does not carry one or
    /// its field ran past the record's end.
    pub mtime: Option<Stamp>,
    /// The creation time, on the same terms.
    pub ctime: Option<Stamp>,
    /// The access time, on the same terms.
    pub atime: Option<Stamp>,
}

/// Read the four bytes at `at` as a little-endian `u32`, or answer `None`
/// and leave the cursor alone when the record ends first.
fn take_u32(body: &[u8], at: &mut usize) -> Option<u32> {
    let bytes = body.get(*at..at.checked_add(4)?)?;
    *at += 4;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The same for eight bytes.
fn take_u64(body: &[u8], at: &mut usize) -> Option<u64> {
    let bytes = body.get(*at..at.checked_add(8)?)?;
    *at += 8;
    let mut value = 0u64;
    for (i, b) in bytes.iter().enumerate() {
        value |= u64::from(*b) << (8 * i);
    }
    Some(value)
}

/// A FILETIME, 100 ns ticks since 1601-01-01 UTC, as a [`Stamp`]. The
/// sub-second part is inside the tick count, so there is no separate
/// nanosecond field to look for.
fn from_filetime(ticks: u64) -> Stamp {
    // A FILETIME is unsigned and this crate's seconds field is signed, so
    // the division is done in i128 and only the SECONDS are narrowed: the
    // widest FILETIME is about 58,000 years past the unix epoch, which
    // fits an i64 of seconds with room to spare.
    let ticks = i128::from(ticks);
    let secs = ticks / i128::from(FILETIME_TICKS_PER_SECOND) - i128::from(FILETIME_EPOCH_OFFSET);
    let sub = (ticks % i128::from(FILETIME_TICKS_PER_SECOND)) as u32;
    let nanos = sub.saturating_mul(100);
    Stamp {
        at: Timestamp {
            unix_seconds: i64::try_from(secs).unwrap_or(i64::MAX),
            nanos,
        },
        raw: ticks as u64,
        raw_nanos: nanos,
    }
}

/// The bits of a UNIX form nanosecond field that count: its low thirty.
const NANOS_FIELD_MASK: u32 = (1 << 30) - 1;

/// A unix seconds count and its optional nanosecond field as a [`Stamp`].
fn from_unix(seconds: u32, nanos: Option<u32>) -> Stamp {
    let raw_nanos = nanos.unwrap_or(0);
    Stamp {
        at: Timestamp {
            unix_seconds: i64::from(seconds),
            // 3.2.6.1 T5: a nanosecond field of 1,000,000,000 or more is
            // refused by nothing. The reference shows the field modulo
            // 2^30 (1,500,000,000 as ,426258176), and so does this; what
            // is left at or above a second after that is not established,
            // and such a time carries no fraction. The field is reported
            // raw beside the seconds either way.
            nanos: Some(raw_nanos & NANOS_FIELD_MASK)
                .filter(|&n| n < 1_000_000_000)
                .unwrap_or(0),
        },
        raw: u64::from(seconds),
        raw_nanos,
    }
}

/// Parse one extra TIME record's body (everything after the record type
/// vint). Answers `None` only when the body is too short to hold even the
/// flags word, which a well-formed record never is.
pub(crate) fn parse(body: &[u8]) -> Option<Times> {
    let mut at = 0usize;
    let flags = crate::read::vint::read(body, &mut at)?;
    let unix_form = flags & TF_UNIX != 0;
    let present = [
        flags & TF_MTIME != 0,
        flags & TF_CTIME != 0,
        flags & TF_ATIME != 0,
    ];
    let mut out = [None, None, None];

    if unix_form {
        // The UNIX form comes in TWO blocks: every present time's seconds
        // field first, then, when 0x0010 is set, every present time's
        // nanosecond field in the same order. The nanosecond flag belongs
        // to the record and not to a time, so a whole-second time still
        // gets four zero bytes of its own.
        let mut seconds = [None, None, None];
        for (slot, want) in present.iter().enumerate() {
            if *want {
                seconds[slot] = take_u32(body, &mut at);
            }
        }
        for (slot, want) in present.iter().enumerate() {
            let nanos = if *want && flags & TF_NANO != 0 {
                take_u32(body, &mut at)
            } else {
                None
            };
            out[slot] = seconds[slot].map(|s| from_unix(s, nanos));
        }
    } else {
        // The WINDOWS form is one block of one u64 per present time, with
        // the sub-second part inside the FILETIME.
        for (slot, want) in present.iter().enumerate() {
            if *want {
                out[slot] = take_u64(body, &mut at).map(from_filetime);
            }
        }
    }

    Some(Times {
        flags,
        unix_form,
        mtime: out[0],
        ctime: out[1],
        atime: out[2],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec F 5.3: `13 40 b7 ac 6a 15 cd 5b 07` is the unix form, mtime
    /// only, 1,789,704,000 s plus 123,456,789 ns, and no other time.
    #[test]
    fn spec_f_5_3_unix_form_with_nanoseconds() {
        let t = parse(&[0x13, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07]).unwrap();
        assert!(t.unix_form);
        let m = t.mtime.unwrap();
        assert_eq!(m.at.unix_seconds, 1_789_704_000);
        assert_eq!(m.at.nanos, 123_456_789);
        assert_eq!(m.raw, 1_789_704_000);
        assert_eq!(t.ctime, None);
        assert_eq!(t.atime, None);
    }

    /// Spec F 5.3: `02 77 f2 f7 db 05 d6 dc 01` is the windows form, mtime
    /// only, FILETIME 134,217,409,567,912,567, which is
    /// 2026-04-27 05:22:36.791256700 UTC.
    #[test]
    fn spec_f_5_3_windows_form() {
        let t = parse(&[0x02, 0x77, 0xf2, 0xf7, 0xdb, 0x05, 0xd6, 0xdc, 0x01]).unwrap();
        assert!(!t.unix_form);
        let m = t.mtime.unwrap();
        assert_eq!(m.raw, 134_217_409_567_912_567);
        assert_eq!(m.at.nanos, 791_256_700);
        let (y, mo, d, hh, mm, ss) = crate::read::dostime::civil(m.at.unix_seconds);
        assert_eq!((y, mo, d, hh, mm, ss), (2026, 4, 27, 5, 22, 36));
        assert_eq!(t.ctime, None);
        assert_eq!(t.atime, None);
    }

    /// Spec F 5.3: `1f 40 b7 ac 6a` declares three times and carries one
    /// seconds field. The modification time reads; the creation and access
    /// times are ABSENT rather than zero, and it is not an error.
    #[test]
    fn spec_f_5_3_a_record_too_short_for_its_flags() {
        let t = parse(&[0x1f, 0x40, 0xb7, 0xac, 0x6a]).unwrap();
        let m = t.mtime.unwrap();
        assert_eq!(m.at.unix_seconds, 1_789_704_000);
        assert_eq!(m.at.nanos, 0);
        assert_eq!(t.ctime, None);
        assert_eq!(t.atime, None);
    }

    /// Spec F 5.3: `33 ...` carries the unknown flag 0x20 beside a valid
    /// 0x13 and reads exactly as `13 ...` does. A reader must not refuse a
    /// member over a flag bit it does not know.
    #[test]
    fn spec_f_5_3_an_unknown_flag_bit_is_ignored() {
        let known = parse(&[0x13, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07]).unwrap();
        let odd = parse(&[0x33, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07]).unwrap();
        assert_eq!(odd.flags, 0x33);
        assert_eq!(odd.mtime, known.mtime);
        assert_eq!(odd.ctime, known.ctime);
        assert_eq!(odd.atime, known.atime);
    }

    /// 3.2.6.1: trailing bytes inside a complete record are ignored.
    #[test]
    fn trailing_bytes_are_ignored() {
        let clean = parse(&[0x13, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07]).unwrap();
        let padded = parse(&[
            0x13, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07, 0xff, 0xff, 0xff,
        ])
        .unwrap();
        assert_eq!(padded, clean);
    }

    /// 3.2.6.1: the two blocks of the unix form, and the fixed order
    /// modification, creation, access. `f18_htime_ma.rar`'s record carries
    /// the modification and access times, so its second seconds field is
    /// the ACCESS time and not the creation time.
    #[test]
    fn the_unix_form_keeps_seconds_and_nanoseconds_in_separate_blocks() {
        let t = parse(&[
            0x1b, 0x40, 0xb7, 0xac, 0x6a, 0x41, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07, 0x16,
            0xcd, 0x5b, 0x07,
        ])
        .unwrap();
        assert_eq!(t.ctime, None);
        let m = t.mtime.unwrap();
        let a = t.atime.unwrap();
        assert_eq!(
            (m.at.unix_seconds, m.at.nanos),
            (1_789_704_000, 123_456_789)
        );
        assert_eq!(
            (a.at.unix_seconds, a.at.nanos),
            (1_789_704_001, 123_456_790)
        );
    }

    /// 3.2.6.1: the record may carry a creation or access time with NO
    /// modification time, which is what `rar -tsm- -tsc` writes.
    #[test]
    fn a_record_can_carry_no_modification_time_at_all() {
        let t = parse(&[0x15, 0x40, 0xb7, 0xac, 0x6a, 0x15, 0xcd, 0x5b, 0x07]).unwrap();
        assert_eq!(t.mtime, None);
        assert_eq!(t.ctime.unwrap().at.unix_seconds, 1_789_704_000);
        assert_eq!(t.ctime.unwrap().at.nanos, 123_456_789);
    }

    /// 3.2.6.1: a nanosecond field above 999,999,999 is clamped by nothing
    /// and refused by nothing. The seconds are reported, the stored figure
    /// is kept, and the converted time carries no fraction.
    #[test]
    fn a_nanosecond_field_out_of_range_is_reported_and_not_refused() {
        let t = parse(&[0x13, 0x40, 0xb7, 0xac, 0x6a, 0xff, 0xff, 0xff, 0xff]).unwrap();
        let m = t.mtime.unwrap();
        assert_eq!(m.at.unix_seconds, 1_789_704_000);
        assert_eq!(m.raw_nanos, u32::MAX);
        assert_eq!(m.at.nanos, 0);
    }

    /// A record with no flags word at all is the one shape that gives
    /// nothing back. It is still not an error: the caller drops the record
    /// and keeps the member.
    #[test]
    fn an_empty_body_carries_no_times() {
        assert_eq!(parse(&[]), None);
    }

    /// Every truncation of a well-formed record parses, carries only the
    /// times whose fields survived, and never panics.
    #[test]
    fn every_truncation_of_a_record_parses() {
        for body in [
            &[0x1f, 0x40, 0xb7, 0xac, 0x6a][..],
            &[0x0e, 0x81, 0x00, 0xc4, 0x4a, 0x19, 0xc1, 0xd5, 0x01][..],
        ] {
            for cut in 0..=body.len() {
                let got = parse(&body[..cut]);
                assert_eq!(got.is_some(), cut > 0, "cut {cut}");
            }
        }
    }
}
