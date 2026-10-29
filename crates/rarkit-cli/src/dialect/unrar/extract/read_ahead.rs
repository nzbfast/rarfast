//! The read-ahead an extract or a test asks of the engine, and the `-tp`
//! window.

use super::*;

/// The read-ahead an extract to disk runs with when no budget is stated:
/// twice the engine's default 4 MiB.
///
/// The seam writes a big stored member one ring slab at a time, past the
/// OS cache ([`unbuffered`]), and its ring is the whole read-ahead in two
/// slabs (`read::seam::ring_plan`): 2 MiB slabs at the engine's default,
/// 4 MiB at this. A drive that takes 4 MiB blocks at its whole rate takes
/// 2 MiB ones slower: on a WD SN8100 (a Windows desktop, Ryzen 7 9800X3D) the 12 GiB
/// member was on disk in 1.34 s with 4 MiB slabs against 1.45 s with 2 MiB,
/// and 8 MiB slabs bought 2 percent more for twice the memory
/// (29 Sep 2026). A stated `-mm` keeps SPEC-API 8.1's
/// own derivation, and `t` and `p` keep the engine's default: their wide
/// read is not the shape this was measured on.
pub(super) const EXTRACT_READ_AHEAD: u64 = 8 << 20;

/// [`EXTRACT_READ_AHEAD`], or what a count names.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_X_READ_AHEAD_MIB` sets it, 8 being the shipped value.
pub(super) fn extract_read_ahead() -> u64 {
    #[cfg(feature = "read-depth-knob")]
    if let Some(mib) = std::env::var("RARFAST_X_READ_AHEAD_MIB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|mib| (1..=256).contains(mib))
    {
        return mib << 20;
    }
    EXTRACT_READ_AHEAD
}

/// The read-ahead the walk reads a COLD, clear, stored archive at for `x`
/// and `e` on macOS when no budget is stated ([`Run::stored_route`]): 256
/// MiB, the seam's two slabs of half of it each.
///
/// **The depth is the deepest counted, and no depth cost a cold row
/// against a shallower one** (M5 Ultra, INDICATIVE, `x` on disk, K=5,
/// against a twin of the shipped 8 MiB, 1 Oct 2026): the
/// many-member set 1.005x at 32 MiB, 1.092x at 64, 1.105x at 128 and 1.135x
/// at 256 (1.644 s to 1.451 s; unrar 1.668 s, a byte copy 1.659 s); the big
/// member beside its sample 1.014x, 1.125x, 1.165x and 1.181x (2.458 s to 2.065
/// s; unrar 2.404 s). What it holds is the two slabs, half the 512 MiB
/// default budget.
#[cfg(feature = "parallel")]
pub(super) const STORED_COLD_READ_AHEAD: u64 = 256 << 20;

/// [`STORED_COLD_READ_AHEAD`], never under `shipped`, or what a count
/// names (feature `read-depth-knob`: `RARFAST_X_READ_AHEAD_MIB`, which
/// then states the depth of every extract).
#[cfg(feature = "parallel")]
pub(super) fn stored_cold_read_ahead(shipped: u64) -> u64 {
    #[cfg(feature = "read-depth-knob")]
    if std::env::var_os("RARFAST_X_READ_AHEAD_MIB").is_some() {
        return shipped;
    }
    shipped.max(STORED_COLD_READ_AHEAD)
}

/// The read-ahead `t` and `p` run with on macOS when no budget is stated:
/// 32 MiB, eight times the engine's default, so the wide read of a big
/// stored member (`read::wide`, which asks for 1 MiB pieces on macOS)
/// keeps as many readers as the width allows, up to thirty-two, where the
/// default's budget held it to four. A narrower Mac keeps one reader a
/// lane and takes larger pieces (twenty readers of about 1.6 MiB on
/// twenty cores).
///
/// **Why depth.** On the M5 Ultra (Mac Studio, 36 cores, internal SSD)
/// the drive reads 14,080 MiB/s past the cache and one reader in order
/// through the cache 13,900, yet four readers of 1 MiB tested the cold
/// big member at 0.85 of that and an 8-volume many-member set at only 0.76: each
/// volume's reads drain at its end, and a split member is joined fragment
/// by fragment (spec F 3.5.4) (the first lever of the cold big-media study,
/// 30 Sep 2026). Timed in one knob binary against 4 MiB
/// (30 Sep 2026, INDICATIVE, load 3 to 6): cold big member
/// `t` 1.13x and the many-member set 1.27x at 16 MiB, level again at 32; warm
/// big member `t` 1.25x at 16 and 1.52x at 32 (0.102 s against 0.155), so 32 by
/// the wall-first rule. On an M1 Ultra (20 cores) 32 was level or better
/// than 16 on every row, warm big member `t` 1.25x over 16. The price at 32,
/// against 4 MiB warm, is 0.9 to 1.4 CPU s and 27 to 51 MiB more.
///
/// **Why only `t` and `p`, and only macOS.** `x` keeps
/// [`EXTRACT_READ_AHEAD`]: its stored member is written through the seam,
/// not read wide, and macOS cold `x` is at the drive's read-plus-write
/// ceiling already. On Linux the wide read holds sixteen readers under the
/// default budget (its pieces split the budget across the width), and
/// more readers than that lost cold there. A stated `-mm` keeps SPEC-API
/// 8.1's own derivation, as it does for `x`.
#[cfg(target_os = "macos")]
pub(super) const TEST_READ_AHEAD: u64 = 32 << 20;

/// [`TEST_READ_AHEAD`] where it applies; `default` (the engine's own
/// derivation, unchanged) everywhere else.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_TP_READ_AHEAD_MIB` sets it on macOS, 4 being the path before
/// this lever.
#[cfg(target_os = "macos")]
pub(super) fn test_read_ahead(default: u64) -> u64 {
    let _ = default;
    #[cfg(feature = "read-depth-knob")]
    if let Some(mib) = std::env::var("RARFAST_TP_READ_AHEAD_MIB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|mib| (1..=256).contains(mib))
    {
        return mib << 20;
    }
    TEST_READ_AHEAD
}

#[cfg(not(target_os = "macos"))]
#[inline(always)]
pub(super) fn test_read_ahead(default: u64) -> u64 {
    default
}

/// The read-ahead the command's ONE session is opened with (`run`), before
/// any volume is read: `default` is the engine's own derivation.
///
/// A set whose headers are encrypted is read through that session and not
/// through options the walk makes later (`Run::walk`), so what the walk
/// would state for the command has to be stated here too, or such a set
/// reads at the engine's default where its twin under `-p` reads at the
/// walk's depth. A stated memory cap (`capped`) keeps SPEC-API 8.1's own
/// derivation, as it does in the walk.
pub(super) fn session_read_ahead(mode: Mode, capped: bool, default: u64) -> u64 {
    if capped {
        return default;
    }
    match mode {
        Mode::Extract { .. } => extract_read_ahead(),
        Mode::Test | Mode::Print => test_read_ahead(default),
    }
}

/// The share of the wide window a lane of the read's width is given by
/// [`wide_test_read_ahead`]: 256 KiB, the piece sixteen lanes already read
/// under the shipped 4 MiB.
pub(super) const WIDE_TEST_PIECE: u64 = 256 << 10;

/// The read-ahead of `t` and `p` where the read is WIDER than the shipped
/// read-ahead holds pieces for ([`tp_window_knob`]): `shipped`, or a
/// [`WIDE_TEST_PIECE`] for every lane of `width` where that is more, never
/// more than a sixty-fourth of the policy's `working_limit`.
///
/// **Why.** The wide read of one stored member keeps the pieces its
/// read-ahead holds, and no piece is under 128 KiB, so the shipped 4 MiB is
/// thirty-two readers of 128 KiB however wide the box: a 12.9 GB member is
/// then about 98,000 pieces, each handed to a reader and joined. On 48
/// cores and 96 threads (a Xeon 8488C, warm, K=5, the box at load 12 to 21
/// so the walls are indicative) that plan tested the member in 0.127 s and
/// printed it in 0.182 s on 2.19e9 instructions and 50,000 context
/// switches; under a 32 MiB read-ahead 0.086 s and 0.112 s on 1.62e9 and
/// 5,500, and under 128 MiB slower again (0.113 s, 92 MiB at the peak). A
/// probe of the same file says the window's SLACK is the other half:
/// forty-eight readers of 128 KiB under forty-eight pieces 0.115 s, under
/// ninety-six 0.083 s (2 Oct 2026).
///
/// **Why a piece a lane and not one figure.** On 8 cores and 16 threads
/// the copy out of the page cache is bound by memory at any read-ahead to
/// 16 MiB (0.251 s at every arm), and past it the pieces leave the cores'
/// caches: `p` 0.80x at 32 MiB and 0.38x at 64. Sixteen lanes of 256 KiB
/// are the shipped 4 MiB, so that box and every narrower one reads as it
/// did, and so does a stated `-mt` of sixteen or less on any box.
///
/// **One volume.** The caller applies it to a set of one volume only. A
/// member split across volumes is read a fragment at a time, each
/// fragment a wide read of its own, and under the deeper read-ahead the
/// same box tested the big member in 123 volumes of 100 MB in 0.342 s against
/// 0.278 s and printed it in 1.385 s against 0.616 s (K=3, load 2 to 4).
///
/// **Its memory.** A sixty-fourth of the working limit is the share
/// `MemoryPolicy::from_limit` gives the read-ahead; the default limit is a
/// quarter of physical memory (512 MiB at least), lowered to a cgroup cap
/// or an address-space limit of the process's environment, so under a cap
/// whose share is below the shipped read-ahead this is `shipped`. A stated
/// `-mm` never reaches here (SPEC-API 8.1's own derivation stands).
pub(super) fn wide_test_read_ahead(shipped: u64, width: usize, working_limit: u64) -> u64 {
    let lanes = (width as u64).saturating_mul(WIDE_TEST_PIECE);
    shipped.max(lanes.min(working_limit / 64))
}

/// The smallest stored member [`tp_window_members`] takes the deeper
/// read-ahead for: 4 GiB, the smallest that has a row.
pub(super) const WIDE_TEST_MEMBER: u64 = 4 << 30;

/// Whether the members a `t` or `p` reads are ones the deeper read-ahead
/// ([`wide_test_read_ahead`]) is for: at least one stored member of
/// [`WIDE_TEST_MEMBER`] or more, and no stored member the wide read takes
/// (its floor, [`WIDE_READ_FLOOR`], or more) that is smaller than that or
/// whose checksum is not a CRC32. Members under the floor, directories and
/// compressed members are not the wide read's and do not count.
///
/// **Why the size.** Every wide read of a member starts its readers and
/// their buffers afresh, and under the deeper read-ahead that is more of
/// both: on 48 cores and 96 threads `p` of sixty-four stored members of
/// 64 MiB took 0.852 s against 0.289 s (K=3), 9 ms more a member, where
/// one member of 4 GiB printed in 0.040 s against 0.060 s and one of
/// 12.9 GB in 0.082 s against 0.160 s. No size between has a row, so the
/// rule keeps to what was measured.
///
/// **Why the checksum.** A BLAKE2sp member's wall is its hash, and the
/// deeper read-ahead bought it nothing: the 12.9 GB member with `-htb`
/// tested in 3.689 s against 3.627 s and printed in 3.889 s against
/// 3.666 s (2 Oct 2026).
pub(super) fn tp_window_members<'m>(members: impl Iterator<Item = &'m Member>) -> bool {
    let mut large = false;
    for member in members {
        if member.is_dir || member.method != 0 || member.size < WIDE_READ_FLOOR {
            continue;
        }
        if member.size < WIDE_TEST_MEMBER || member.crc32.is_none() {
            return false;
        }
        large = true;
    }
    large
}

/// How `t` and `p` take the deeper read-ahead ([`wide_test_read_ahead`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TpWindow {
    /// Never: the shipped read-ahead.
    Off,
    /// By the rule: a set of one volume whose stored members are large
    /// ones with a CRC32 ([`tp_window_members`]).
    Rule,
    /// On every set, whatever its volumes and members: the arm the rule's
    /// two conditions were counted against, and what
    /// `tests/tp_window.rs` reads a small member under.
    Always,
}

/// What ships, with `RARFAST_TP_WINDOW` unset: the rule on Linux, where
/// its rows are (2 Oct 2026: 48 cores and 96
/// threads of x86-64, `t` of a 12.9 GB stored member 1.41x and `p` 1.92x;
/// 64 cores of aarch64 1.30x and 1.47x; 8 cores and 16 threads level, as
/// every row the rule does not reach). OFF elsewhere: macOS ships a
/// read-ahead the rule does not exceed under 129 lanes, and no other
/// system has a row.
pub(super) const TP_WINDOW: TpWindow = if cfg!(target_os = "linux") {
    TpWindow::Rule
} else {
    TpWindow::Off
};

/// [`TP_WINDOW`], unless `RARFAST_TP_WINDOW` says otherwise: a RUNTIME
/// knob, like `RARFAST_COLD_WINDOW`, so one binary prices the rule against
/// the shipped read-ahead.
pub(super) fn tp_window_knob() -> TpWindow {
    static ON: std::sync::OnceLock<TpWindow> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        tp_window_of(
            crate::knob::reader_var("RARFAST_TP_WINDOW").ok().as_deref(),
            TP_WINDOW,
        )
    })
}

/// [`tp_window_knob`]'s reading of the variable's value, in any case and
/// with space around it: `1`, `on` or `width` is the rule, `0` or `off`
/// off, `always` every set; `shipped` for anything else and for no value
/// at all.
pub(super) fn tp_window_of(value: Option<&str>, shipped: TpWindow) -> TpWindow {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on" | "width") => TpWindow::Rule,
        Some("0" | "off") => TpWindow::Off,
        Some("always") => TpWindow::Always,
        _ => shipped,
    }
}
