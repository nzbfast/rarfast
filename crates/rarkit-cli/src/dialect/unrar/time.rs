//! Local-time rendering, because that is what the reference prints.
//!
//! unrar shows a member's timestamp in the BOX's time zone, and the
//! committed conformance tables carry the result: the same archive lists
//! as `2001-09-08 21:46` in the macOS table and `2001-09-09 02:46` in the
//! Windows one. So a drop-in cannot print UTC, and it cannot print a
//! fixed offset either, since the fixture's instant falls inside a summer
//! time period whose rule is historical.
//!
//! The workspace forbids `unsafe`, so `libc::localtime_r` is not
//! available to us, and the standard library has no time zone. `jiff`
//! reads the platform zone (the IANA database on Unix, a bundled copy on
//! Windows) in safe Rust and gets the historical rule right, which is why
//! it is a dependency of this crate.
//!
//! `TimeZone::system()` is not used directly on Unix: it resolves through
//! `jiff::tz::db()`, and building that database walks every file under
//! the zoneinfo directory (measured: 94% of a listing process's CPU,
//! 14 Sep 2026) even though only
//! one zone is ever needed. `system_time_zone` below reads the single
//! TZif file behind `/etc/localtime` directly instead, with no directory
//! walk, and falls back to `TimeZone::system()` whenever that shortcut
//! cannot apply (a `TZ` override, or `/etc/localtime` missing or
//! unreadable) so behaviour and fallback stay exactly what jiff would
//! have produced. Windows is untouched: jiff resolves its zone from the
//! registry there, not by walking a directory, so the cost this works
//! around does not apply.

use std::sync::OnceLock;

use jiff::tz::TimeZone;
use jiff::Timestamp;

/// The box's local time zone, resolved once per process.
fn system_time_zone() -> TimeZone {
    static SYSTEM: OnceLock<TimeZone> = OnceLock::new();
    SYSTEM.get_or_init(resolve_system_time_zone).clone()
}

#[cfg(unix)]
fn resolve_system_time_zone() -> TimeZone {
    // A `TZ` override is rare in this CLI's own use and only needs to be
    // correct, not fast - jiff's own database-backed resolution already
    // handles every form (an IANA name, a POSIX rule, or a TZif path).
    if std::env::var_os("TZ").is_some() {
        return TimeZone::system();
    }
    read_etc_localtime().unwrap_or_else(TimeZone::system)
}

#[cfg(not(unix))]
fn resolve_system_time_zone() -> TimeZone {
    TimeZone::system()
}

/// Reads `/etc/localtime`'s TZif bytes directly into a `TimeZone`,
/// without building jiff's whole zoneinfo database. Mirrors jiff's own
/// Unix heuristic (`jiff::tz::system::unix::read_link_to_zoneinfo`): if
/// the path is a symlink into a `zoneinfo/` tree, its suffix is the IANA
/// name; otherwise the `TimeZone` is unnamed, exactly as jiff falls back.
/// The name only affects diagnostics and round-trip formatting, never the
/// offsets this CLI reads out of it.
#[cfg(unix)]
fn read_etc_localtime() -> Option<TimeZone> {
    const PATH: &str = "/etc/localtime";
    let name = std::fs::read_link(PATH)
        .ok()
        .and_then(|target| target.to_str().map(str::to_owned))
        .and_then(|target| {
            let needle = "zoneinfo/";
            target
                .rfind(needle)
                .map(|pos| target[pos + needle.len()..].to_owned())
        })
        .unwrap_or_else(|| PATH.to_owned());
    let data = std::fs::read(PATH).ok()?;
    TimeZone::tzif(&name, &data).ok()
}

/// A broken-down local time, in the fields unrar prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Local {
    /// Four-digit year.
    pub(crate) year: i16,
    /// 1-12.
    pub(crate) month: i8,
    /// 1-31.
    pub(crate) day: i8,
    /// 0-23.
    pub(crate) hour: i8,
    /// 0-59.
    pub(crate) minute: i8,
    /// 0-60.
    pub(crate) second: i8,
    /// Nanoseconds within the second.
    pub(crate) nanosecond: i32,
}

/// Breaks a Unix instant down in the box's own zone.
///
/// Falls back to UTC when the platform has no usable zone, which is the
/// same fallback the reference's own C library makes and keeps a listing
/// readable rather than empty.
pub(crate) fn local(unix_seconds: i64) -> Option<Local> {
    let stamp = Timestamp::from_second(unix_seconds).ok()?;
    let zoned = stamp.to_zoned(system_time_zone());
    Some(Local {
        year: zoned.year(),
        month: zoned.month(),
        day: zoned.day(),
        hour: zoned.hour(),
        minute: zoned.minute(),
        second: zoned.second(),
        nanosecond: zoned.subsec_nanosecond(),
    })
}

/// Breaks an instant down with NO zone applied, for a member whose stored
/// time is a wall clock rather than an instant.
///
/// A DOS date-and-time word (every format before RAR 5) carries no zone at
/// all, and the reference prints its fields as they are stored. rarkit reads
/// such a word AS UTC and says so (`read/dostime.rs`: "the caller decides
/// what to do about that"), so rendering it back in UTC reproduces the
/// stored wall clock exactly. Measured against unrar 7.23 on an Apple Silicon Mac over
/// `fixtures/legacy/archives/d140_m0.rar`: the reference lists
/// `2020-09-13 12:26` and applying the box's zone gave `08:26`.
pub(crate) fn wall(unix_seconds: i64) -> Option<Local> {
    let stamp = Timestamp::from_second(unix_seconds).ok()?;
    let zoned = stamp.to_zoned(TimeZone::UTC);
    Some(Local {
        year: zoned.year(),
        month: zoned.month(),
        day: zoned.day(),
        hour: zoned.hour(),
        minute: zoned.minute(),
        second: zoned.second(),
        nanosecond: zoned.subsec_nanosecond(),
    })
}

/// The instant a stored wall clock names in the box's own zone: what
/// extraction sets on the file, and what a time switch compares.
///
/// `unix_seconds` is the wall clock as the engine reads it, AS UTC (see
/// [`wall`]). Reference unrar 7.23 reads it as local time (sweep 2 item
/// 38, measured 8 Oct 2026 on macOS arm64 under five zones;
/// `tests/rar4_times_local.rs` has the table): a clock the zone skips goes
/// forward by the skipped hour, and one it has twice is the second, the
/// winter one, which is jiff's `later` on both counts. `None` only for a
/// time no calendar holds, and the caller then keeps the UTC reading.
pub(crate) fn wall_to_instant(unix_seconds: i64) -> Option<i64> {
    let clock = Timestamp::from_second(unix_seconds)
        .ok()?
        .to_zoned(TimeZone::UTC)
        .datetime();
    let stamp = system_time_zone()
        .to_ambiguous_timestamp(clock)
        .later()
        .ok()?;
    Some(stamp.as_second())
}

/// [`local`] or [`wall`], by whether the member's stored time is an instant.
fn broken_down(unix_seconds: i64, wall_clock: bool) -> Option<Local> {
    if wall_clock {
        wall(unix_seconds)
    } else {
        local(unix_seconds)
    }
}

/// `YYYY-MM-DD HH:MM`, the form the `l` and `v` tables use.
pub(crate) fn short(unix_seconds: i64, wall_clock: bool) -> String {
    match broken_down(unix_seconds, wall_clock) {
        Some(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            t.year, t.month, t.day, t.hour, t.minute
        ),
        None => "                ".to_owned(),
    }
}

/// `YYYY-MM-DD HH:MM:SS,nnnnnnnnn`, the form the technical listing uses.
/// The comma is the reference's, not a typo, and the nanoseconds are nine
/// digits wide whether or not the archive carried sub-second precision.
///
/// `nanos` is the member's own fraction of a second. Until 9 Oct 2026 the
/// time was broken down from whole seconds alone and every member listed
/// `,000000000` (rar and unrar 7.23 list `,099958648` for the same
/// member, `tests/lt_nanoseconds.rs`).
pub(crate) fn technical(unix_seconds: i64, nanos: u32, wall_clock: bool) -> String {
    match broken_down(unix_seconds, wall_clock) {
        Some(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:09}",
            t.year, t.month, t.day, t.hour, t.minute, t.second, nanos
        ),
        None => String::new(),
    }
}

/// Turns the six numbers of a date switch (year, month, day, hour,
/// minute, second) into a Unix instant, reading them as LOCAL time the
/// way the reference does, so `-ta2020-01-01` means midnight where the
/// caller is.
///
/// A number may run past its range, and is carried over as the C
/// library's `mktime` carries it, which is what the reference's `-ta` and
/// `-tb` show (unrar 7.23, measured 8 Oct 2026: `2023-13-45` is 14 Feb
/// 2024 and `2023-11-00` is 31 Oct 2023). Until sweep 2 item 36 such a
/// date was `None` here, and the switch then filtered nothing.
///
/// NOT CARRIED from the predecessor, whose date arithmetic was done by
/// hand through a helper the whole-tree census at the fork point marks as
/// not to be carried. jiff is already a dependency of this crate and
/// resolves a civil date in a zone itself, picking the right side of a
/// daylight-saving fold.
///
/// `None` for a year no calendar here holds.
pub(crate) fn carried_civil_to_unix(fields: [i64; 6]) -> Option<i64> {
    let [year, month, day, hour, minute, second] = fields;
    let start = jiff::civil::Date::new(i16::try_from(year).ok()?, 1, 1)
        .ok()?
        .to_datetime(jiff::civil::Time::midnight());
    // One unit at a time, largest first: a span's units share one sign,
    // and `2023-11-00` is ten months on and one day back.
    let span = jiff::Span::new();
    let zoned = start
        .checked_add(span.try_months(month - 1).ok()?)
        .ok()?
        .checked_add(span.try_days(day - 1).ok()?)
        .ok()?
        .checked_add(span.try_hours(hour).ok()?)
        .ok()?
        .checked_add(span.try_minutes(minute).ok()?)
        .ok()?
        .checked_add(span.try_seconds(second).ok()?)
        .ok()?
        .to_zoned(system_time_zone())
        .ok()?;
    Some(zoned.timestamp().as_second())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_technical_form_carries_nine_nanosecond_digits_and_a_comma() {
        let rendered = technical(1_000_000_000, 0, false);
        assert!(
            rendered.ends_with(",000000000"),
            "expected the reference's comma-and-nine-digits tail, got {rendered}"
        );
        assert_eq!(rendered.len(), "2001-09-08 21:46:40,000000000".len());
    }

    #[test]
    fn the_short_form_is_the_width_the_listing_columns_assume() {
        assert_eq!(short(1_000_000_000, false).len(), "2001-09-08 21:46".len());
    }

    #[test]
    fn a_civil_stamp_round_trips_through_the_local_zone() {
        // Whatever zone the machine is in, reading a wall-clock stamp and
        // formatting the instant back must give the same wall clock.
        let at = carried_civil_to_unix([2020, 1, 1, 0, 0, 0]).expect("a real date");
        assert_eq!(short(at, false), "2020-01-01 00:00");
    }

    #[test]
    fn a_number_past_its_range_carries_over() {
        // As the reference's `-ta` reads them (sweep 2 item 36).
        let at = |fields| carried_civil_to_unix(fields).expect("a date");
        assert_eq!(
            short(at([2023, 13, 45, 0, 0, 0]), false),
            "2024-02-14 00:00"
        );
        assert_eq!(short(at([2023, 2, 30, 0, 0, 0]), false), "2023-03-02 00:00");
        assert_eq!(short(at([2023, 11, 0, 0, 0, 0]), false), "2023-10-31 00:00");
        assert_eq!(short(at([2023, 0, 10, 0, 0, 0]), false), "2022-12-10 00:00");
        assert!(carried_civil_to_unix([99_999, 1, 1, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_wall_clock_stamp_is_rendered_with_no_zone_applied() {
        // A DOS date-and-time word is a wall clock that rarkit hands over
        // as though it were UTC, so rendering it back in UTC reproduces
        // exactly what the archive stored - in any box zone. Measured
        // against unrar 7.23 over fixtures/legacy/archives/d140_m0.rar,
        // which the reference lists as `2020-09-13 12:26`.
        assert_eq!(short(1_599_999_960, true), "2020-09-13 12:26");
    }
}
