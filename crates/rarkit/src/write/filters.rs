//! `FilterPolicy::Detect` for the RAR 5 writer (spec G section 3.8.2).
//!
//! This package decides WHICH filter runs over which bytes; the encoder
//! transforms and writes the record (spec H3 section 6.6,
//! `encode::filter`). The choice is made per REGION by sampling:
//!
//! - A region is the format's longest filter span, `0x3ffff` bytes
//!   (SPEC-C 6.4, and H2 section 0's bound, which rarkit's reader
//!   enforces). Regions start on the encoder's parse block boundaries,
//!   which are `0x40000` apart from the start of what the encoder is
//!   handed, so a region's record is written by the block it starts in
//!   and a span never straddles a chunk. The last byte of each full
//!   block is left unfiltered; that is the price of the bound, and it
//!   is one byte in 262,144.
//! - Within a region, three probe windows of 16 KiB, at the front, the
//!   middle and the back, collapsing when the region is too short to hold
//!   three apart.
//! - Each window is priced by [`Probe`], the estimate of 3.8.2 (one greedy
//!   pass, two candidate copies a position, fixed charges), once
//!   unfiltered and once per candidate, and the smallest total wins.
//! - Stage one tries the byte-lane deltas of 1, 2 and 4 channels, x86
//!   call and jump (type 2) and ARM (type 3): six probes with the
//!   unfiltered one. Its WINNER is the smallest of the six, the
//!   unfiltered probe included, so a region that votes for nothing pays
//!   six probes and no more.
//! - Stage two, by what won stage one:
//!   - x86 call and jump: x86 calls alone (type 1) too;
//!   - a delta: the lag screen's picks (below) that pass the pre-screen's
//!     order-0 test; without the pre-screen, the whole list of wider and
//!     odd strides 3, 6, 8, 12, 16, 24 and 32;
//!   - otherwise, where no address transform beat the unfiltered probe
//!     by the keeping bar, the LAG SCREEN ([`lags`]): equal bytes at each
//!     lag 1 to 32 over the front probe window, and a delta of each of
//!     the (at most two) lags that stand out. This is what finds 24-bit
//!     stereo (6) and six-channel 16-bit audio (12), whose deltas of 1, 2
//!     and 4 all lose to the unfiltered bytes, and it costs text nothing
//!     but the count, because no lag stands out there.
//!
//!   The split of the three address transforms, the strides and the
//!   screen were decided on 27 Sep 2026, ahead of the text of
//!   3.8.2; 6 and 12 are the strides
//!   reference `rar` 7.23 was seen writing.
//! - A filter is kept only when it beats the unfiltered probe by MORE
//!   than 2 per cent; a tie keeps the bytes unfiltered.
//!
//! One shortcut, which cannot change a verdict: an address transform
//! that leaves every probe window's bytes as they were would code them
//! exactly as the unfiltered probe did, and so cannot beat it by 2 per
//! cent, so it is not coded at all. On data with no executable in it that
//! is most of the address probes.
//!
//! **Determinism** (API promise 6). A verdict is a function of the
//! region's own bytes and its member offset and nothing else: the probe
//! sizes its output in whole bits from integer code lengths, never from a
//! floating point entropy, so the same bytes choose the same filter on
//! every platform, and regions are independent of each other, so the
//! order they are judged in, and the thread each is judged on, cannot
//! move a byte.

use crate::carry::c_lz::codec::rar50::log2_sixteenths;
use crate::carry::h_ours::codec::rar50::tree::common_prefix;
use crate::encode::drive::PARSE_BLOCK_BYTES;
use crate::encode::filter::{encode_in_place, FilterKind, FilterSpan, MAX_SPAN};

/// The length of one probe window.
const PROBE_BYTES: usize = 16 << 10;

/// A region shorter than this is not judged: its record and the table
/// room symbol 256 takes would eat whatever a transform saved, and a
/// probe of a few dozen bytes says nothing about it.
const LEAST_REGION_BYTES: usize = 512;

/// A kept filter's probe total must be under this many fiftieths of the
/// unfiltered total: more than 2 per cent smaller.
const KEEP_FIFTIETHS: u64 = 49;

/// Roughly what a record costs in the stream: symbol 256's code and the
/// fields of a 3 byte length, charged to every filtered probe so a
/// transform that saves a few bits of a tiny window does not win.
const RECORD_BITS: u64 = 48;

/// Stage one's candidates, in the order a tie is settled: the earlier
/// wins.
const STAGE_ONE: [FilterKind; 5] = [
    FilterKind::Delta(1),
    FilterKind::Delta(2),
    FilterKind::Delta(4),
    FilterKind::X86CallJump,
    FilterKind::Arm,
];

/// Stage two after a delta win.
const WIDE_DELTAS: [FilterKind; 7] = [
    FilterKind::Delta(3),
    FilterKind::Delta(6),
    FilterKind::Delta(8),
    FilterKind::Delta(12),
    FilterKind::Delta(16),
    FilterKind::Delta(24),
    FilterKind::Delta(32),
];

/// The lag screen looks at lags 1 to this.
const LAGS: usize = 32;

/// A lag stands out when its count of equal bytes is more than this many
/// halves of the mean count over all [`LAGS`] lags (one and a half times
/// it) ...
const LAG_OVER_MEAN_HALVES: usize = 3;

/// ... and at least this fraction of the window's positions, so a window
/// where nothing repeats at any lag cannot stand a lag out on noise.
const LAG_LEAST_SHARE: usize = 32;

/// The lowest level `FilterPolicy::Detect` judges at: 2, because level 1
/// writes no filter (decided 27 Sep 2026, "like rar": reference
/// `rar` 7.23 writes none at `-m1` either). Level 3 parses a filtered
/// block lazily and level 5 at its full effort (`encode::drive`'s
/// `effort_for`). A bench build may lower it to 1 with
/// `RARKIT_FILTER_LEAST_LEVEL=1`, which is the record that was decided
/// on.
pub(crate) fn least_level() -> u8 {
    #[cfg(feature = "bench-internals")]
    {
        static LEAST: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
        *LEAST.get_or_init(|| {
            std::env::var("RARKIT_FILTER_LEAST_LEVEL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(LEAST_LEVEL)
        })
    }
    #[cfg(not(feature = "bench-internals"))]
    LEAST_LEVEL
}

/// See [`least_level`].
const LEAST_LEVEL: u8 = 2;

/// The plan for `bytes`, whose first byte sits `base` bytes into its
/// member: one span per region a filter pays in, ascending and disjoint,
/// relative to `bytes`. Appended to `plan`, which is cleared first.
pub(crate) fn detect(bytes: &[u8], base: u64, plan: &mut Vec<FilterSpan>) {
    plan.clear();
    let regions = bytes.len().div_ceil(PARSE_BLOCK_BYTES);
    let judge = |index: usize| -> Option<FilterSpan> {
        let start = index * PARSE_BLOCK_BYTES;
        let end = (start + MAX_SPAN).min(bytes.len());
        if end - start < LEAST_REGION_BYTES {
            return None;
        }
        #[cfg(feature = "bench-internals")]
        if let Some(forced) = forced() {
            return forced.map(|kind| FilterSpan {
                start,
                len: end - start,
                kind,
            });
        }
        let kind = PROBE.with(|probe| {
            probe
                .borrow_mut()
                .judge(&bytes[start..end], base + start as u64)
        })?;
        Some(FilterSpan {
            start,
            len: end - start,
            kind,
        })
    };
    #[cfg(feature = "parallel")]
    if regions > 1 {
        use rayon::prelude::*;
        let verdicts: Vec<Option<FilterSpan>> = (0..regions).into_par_iter().map(judge).collect();
        plan.extend(verdicts.into_iter().flatten());
        return;
    }
    plan.extend((0..regions).filter_map(judge));
}

/// Every candidate's probe total over `region`, for the bench seam
/// (`internals::filter_probe_totals`): the unfiltered one first.
#[cfg(feature = "bench-internals")]
pub(crate) fn probe_totals(region: &[u8], f: u64) -> Vec<(String, u64)> {
    let mut probe = Probe::new();
    let (windows, count) = windows(region.len());
    let windows = &windows[..count];
    let plain = windows.iter().map(|w| probe.cost(&region[w.clone()])).sum();
    let mut out = vec![("None".to_string(), plain)];
    let screened = lags(&region[windows[0].clone()]);
    out.push((format!("screen={screened:?}"), 0));
    for kind in STAGE_ONE
        .iter()
        .chain(&WIDE_DELTAS)
        .chain(&[FilterKind::X86Call])
    {
        if let Some(total) = probe.filtered_cost(region, f, windows, *kind) {
            out.push((format!("{kind:?}"), total));
        }
    }
    out
}

/// A verdict forced on every region instead of judging, only in a bench
/// build, read once from `RARKIT_FILTER_FORCE`:
///
/// - `off`: no filter anywhere, which is today's archive from the same
///   binary, so `gate.py --knob RARKIT_FILTER_FORCE=off:detect` pairs
///   Detect against no filters across processes on any create leg;
/// - `e8`, `e8e9`, `arm`, `delta<N>`: that transform on every region, for
///   the count's "what would this buy everywhere" rows;
/// - anything else, `detect` included, or unset: judge as shipped.
#[cfg(feature = "bench-internals")]
fn forced() -> Option<Option<FilterKind>> {
    static FORCED: std::sync::OnceLock<Option<Option<FilterKind>>> = std::sync::OnceLock::new();
    *FORCED.get_or_init(|| {
        let value = std::env::var("RARKIT_FILTER_FORCE").ok()?;
        match value.as_str() {
            "off" => Some(None),
            "e8" => Some(Some(FilterKind::X86Call)),
            "e8e9" => Some(Some(FilterKind::X86CallJump)),
            "arm" => Some(Some(FilterKind::Arm)),
            other => other
                .strip_prefix("delta")
                .and_then(|n| n.parse().ok())
                .filter(|n| (1..=32).contains(n))
                .map(|n| Some(FilterKind::Delta(n))),
        }
    })
}

std::thread_local! {
    /// One probe's buffers per thread, so judging a region allocates
    /// nothing once its thread has judged one before.
    static PROBE: std::cell::RefCell<Probe> = std::cell::RefCell::new(Probe::new());
}

/// The windows of a region of `len` bytes: front, middle and back,
/// collapsing to fewer when the region is too short for three apart.
fn windows(len: usize) -> ([std::ops::Range<usize>; 3], usize) {
    let w = PROBE_BYTES.min(len);
    let front = 0..w;
    let back = len - w..len;
    let middle = (len - w) / 2..(len - w) / 2 + w;
    if len <= w {
        ([front, 0..0, 0..0], 1)
    } else if len < 3 * w {
        ([front, back, 0..0], 2)
    } else {
        ([front, middle, back], 3)
    }
}

/// The probe coder and its buffers.
pub(crate) struct Probe {
    /// The position last offered under each [`slot`], STAMPED: the window's
    /// [`Probe::base`] plus the position. A place below the base was
    /// written by an earlier window and reads as empty, as does
    /// [`NO_POSITION`].
    places: Vec<u32>,
    /// The stamp of the window being priced: position 0 of it.
    base: u32,
    /// The first stamp no window has used yet.
    next: u32,
    /// The window as a candidate transform leaves it.
    filtered: Vec<u8>,
    scratch: Vec<u8>,
}

/// The places of the offer's table, one for each value of [`slot`]: 16
/// KiB, which stays in the first level cache beside the window.
const PLACES: usize = 1 << 12;
/// An empty place. A window is under `2^31` bytes, so no position is
/// this.
const NO_POSITION: u32 = u32::MAX;
/// The bytes a place is keyed by, and the shortest copy at a new
/// distance.
const KEY_BYTES: usize = 4;
/// The price's counts: the 256 byte values, then the two below.
const COUNTS: usize = 258;
/// The count of copies at a new distance.
const NEW_COPY: usize = 256;
/// The count of copies at the distance of the copy before.
const REPEAT: usize = 257;
/// The most one counted symbol is charged, in bits: the longest code
/// the format's streams carry.
const LONGEST_CHARGE: u32 = 15;

impl Probe {
    pub(crate) fn new() -> Probe {
        Probe {
            places: vec![NO_POSITION; PLACES],
            base: 0,
            next: 0,
            filtered: Vec::with_capacity(3 * PROBE_BYTES),
            scratch: Vec::with_capacity(PROBE_BYTES),
        }
    }

    /// The filter this region should carry, if one pays. `f` is the
    /// region's member relative start.
    pub(crate) fn judge(&mut self, region: &[u8], f: u64) -> Option<FilterKind> {
        let (windows, count) = windows(region.len());
        let windows = &windows[..count];
        let front = &region[windows[0].clone()];
        let counts = lag_counts(front);
        // The PRE-SCREEN ([`Screen`], shipped 27 Sep 2026): a stage one
        // candidate is coded only where its cheap count says it could
        // pay, and a region where none could is not coded at all.
        let screen = screened().then(|| Screen::of(region, windows, front.len(), &counts));
        if screen.as_ref().is_some_and(Screen::empty) {
            return None;
        }
        let plain: u64 = windows.iter().map(|w| self.cost(&region[w.clone()])).sum();
        // The unfiltered probe stands first: a candidate must be strictly
        // smaller to take its place, so a tie keeps the bytes as they are.
        let mut best: (Option<FilterKind>, u64) = (None, plain);
        let mut address_pays = false;
        for kind in STAGE_ONE {
            if screen.as_ref().is_some_and(|screen| !screen.admits(kind)) {
                continue;
            }
            let total = self.consider(region, f, windows, kind, &mut best);
            if matches!(kind, FilterKind::X86CallJump | FilterKind::Arm) {
                address_pays |= total.is_some_and(|total| keeps(total, plain));
            }
        }
        match best.0 {
            Some(FilterKind::X86CallJump) => {
                self.consider(region, f, windows, FilterKind::X86Call, &mut best);
            }
            Some(FilterKind::Delta(won)) => match screen.as_ref().filter(|_| narrow_stage_two()) {
                // After a delta win, only the lag screen's picks rather
                // than the whole list (shipped 27 Sep 2026).
                Some(screen) => {
                    for lag in screen.lags.into_iter().flatten().filter(|&lag| lag != won) {
                        self.consider(region, f, windows, FilterKind::Delta(lag), &mut best);
                    }
                }
                None => {
                    for kind in WIDE_DELTAS {
                        self.consider(region, f, windows, kind, &mut best);
                    }
                }
            },
            _ => {}
        }
        if !address_pays && !matches!(best.0, Some(FilterKind::Delta(_))) {
            let [first, second] = match &screen {
                Some(screen) => screen.lags,
                None => picked_lags(&counts, front.len()),
            };
            for lag in [first, second].into_iter().flatten() {
                self.consider(region, f, windows, FilterKind::Delta(lag), &mut best);
            }
        }
        let (kind, total) = best;
        kind.filter(|_| keeps(total, plain))
    }

    /// Probe `kind` and keep it in `best` when it is strictly smaller than
    /// every candidate before it, the unfiltered probe included, so a tie
    /// goes to the earlier one. Answers its total, or `None` where an
    /// address transform changed no byte and was not coded.
    fn consider(
        &mut self,
        region: &[u8],
        f: u64,
        windows: &[std::ops::Range<usize>],
        kind: FilterKind,
        best: &mut (Option<FilterKind>, u64),
    ) -> Option<u64> {
        let total = self.filtered_cost(region, f, windows, kind)?;
        if total < best.1 {
            *best = (Some(kind), total);
        }
        Some(total)
    }

    /// The probe total of `windows` of `region` under `kind`, or `None`
    /// when an address transform changes no byte of any of them, which
    /// codes exactly as the unfiltered probe did.
    fn filtered_cost(
        &mut self,
        region: &[u8],
        f: u64,
        windows: &[std::ops::Range<usize>],
        kind: FilterKind,
    ) -> Option<u64> {
        let mut filtered = std::mem::take(&mut self.filtered);
        let mut scratch = std::mem::take(&mut self.scratch);
        // Every window transformed first, so an address transform that
        // touched nothing is known before any of them is coded.
        let mut changed = matches!(kind, FilterKind::Delta(_));
        let mut from = [0usize; 4];
        filtered.clear();
        for (index, window) in windows.iter().enumerate() {
            from[index] = filtered.len();
            filtered.extend_from_slice(&region[window.clone()]);
            let bytes = &mut filtered[from[index]..];
            encode_in_place(kind, bytes, f + window.start as u64, &mut scratch);
            changed |= bytes[..] != region[window.clone()];
        }
        from[windows.len()] = filtered.len();
        let total = changed.then(|| {
            (0..windows.len())
                .map(|index| self.cost(&filtered[from[index]..from[index + 1]]) + RECORD_BITS)
                .sum()
        });
        self.filtered = filtered;
        self.scratch = scratch;
        total
    }

    /// The price of `window` in bits (spec G section 3.8.2, "The
    /// price"), a function of these bytes alone: one greedy pass counts
    /// each byte left as it is and each copy taken, a copy pays a fixed
    /// charge for its length and its distance, and at the end every
    /// count pays [`charge`].
    pub(crate) fn cost(&mut self, window: &[u8]) -> u64 {
        debug_assert!(window.len() < 1 << 31);
        // A fresh table for this window: the stamps move past every place
        // an earlier window wrote, so none of them reads as a position.
        // Filled again only when the stamps would run out, where it was
        // filled for every window, 16 KiB for a member of a few hundred
        // bytes. Screened 15 Oct 2026 on an EPYC 4345P (x86-64, plain
        // builds, the default width, K=9 alternated) over 20,000 small
        // files at level 3: 2.796 CPU s against 2.815 (0.7 percent of the
        // create; the whole screen is about 8), wall level at 0.224 s,
        // every archive byte the same.
        if u64::from(self.next) + window.len() as u64 >= u64::from(NO_POSITION) {
            self.places.fill(NO_POSITION);
            self.next = 0;
        }
        self.base = self.next;
        self.next += window.len() as u32;
        let mut counts = [0u32; COUNTS];
        let mut flat = 0u64;
        let mut last = None;
        let mut at = 0;
        while at < window.len() {
            let offer = if window.len() - at < KEY_BYTES {
                Offer::Nothing
            } else {
                self.offer(window, at, last)
            };
            match offer {
                Offer::Nothing => {
                    counts[usize::from(window[at])] += 1;
                    at += 1;
                }
                Offer::Repeat { length } => {
                    counts[REPEAT] += 1;
                    flat += gamma(length - 2);
                    at += length;
                }
                Offer::NewCopy { length, distance } => {
                    counts[NEW_COPY] += 1;
                    flat += gamma(length - 3) + 4 + digits(distance);
                    last = Some(distance);
                    at += length;
                }
            }
        }
        let total: u64 = counts.iter().map(|&count| u64::from(count)).sum();
        let charged = counts.iter().filter(|&&count| count > 0);
        flat + charged
            .map(|&count| u64::from(count) * charge(count, total))
            .sum::<u64>()
    }

    /// The offer at `at`, which has [`KEY_BYTES`] bytes or more after
    /// it. Two candidates and no more, each measured to its end before
    /// they are compared: the distance of the copy before, then the one
    /// position the table holds for these four bytes. `at` takes that
    /// place whatever comes of it, and a tie goes to the repeat, which
    /// pays for no distance.
    fn offer(&mut self, window: &[u8], at: usize, last: Option<usize>) -> Offer {
        let room = window.len() - at;
        let repeat = last.map_or(0, |distance| common(window, at - distance, at, room));
        let held = std::mem::replace(&mut self.places[slot(window, at)], self.base + at as u32);
        let source =
            (held != NO_POSITION && held >= self.base).then(|| (held - self.base) as usize);
        let fresh = source.map_or(0, |source| common(window, source, at, room));
        match source {
            _ if repeat >= 3 && repeat >= fresh => Offer::Repeat { length: repeat },
            Some(source) if fresh >= 4 => Offer::NewCopy {
                length: fresh,
                distance: at - source,
            },
            _ => Offer::Nothing,
        }
    }
}

/// Whether a filtered probe total beats the unfiltered one by MORE than
/// 2 per cent.
fn keeps(total: u64, plain: u64) -> bool {
    total * 50 < plain * KEEP_FIFTIETHS
}

/// The lag screen: over `window`, how many bytes equal the byte `k`
/// before them, for each lag `k` of 1 to [`LAGS`]; and the (at most two)
/// lags that stand out, most equal bytes first and the shorter lag first
/// on a tie. A lag stands out when its count is over one and a half times
/// the mean of all [`LAGS`] counts and at least one position in
/// [`LAG_LEAST_SHARE`]. Lags 1, 2 and 4 are left out: stage one probed
/// their deltas already.
#[cfg(feature = "bench-internals")]
fn lags(window: &[u8]) -> [Option<u8>; 2] {
    picked_lags(&lag_counts(window), window.len())
}

/// For each lag `k` of 1 to [`LAGS`], how many bytes of `window` equal
/// the byte `k` before them (index 0 unused).
fn lag_counts(window: &[u8]) -> [usize; LAGS + 1] {
    let mut counts = [0usize; LAGS + 1];
    for (lag, count) in counts.iter_mut().enumerate().skip(1) {
        if lag < window.len() {
            *count = equal_bytes(&window[lag..], window);
        }
    }
    counts
}

/// Whether a delta of `lag` channels codes `window` in fewer order-0 bits
/// than `plain`, the window's own. SPEC-J 3.7.1's values in any order,
/// which is all an order-0 size needs: each byte's lane's previous byte
/// (0 before the first) minus the byte.
fn delta_shrinks(window: &[u8], lag: usize, plain: u64) -> bool {
    let head = window[..lag.min(window.len())]
        .iter()
        .map(|&byte| 0u8.wrapping_sub(byte));
    let rest = window
        .iter()
        .zip(window.get(lag..).unwrap_or_default())
        .map(|(&previous, &byte)| previous.wrapping_sub(byte));
    order0_bits(head.chain(rest)) < plain
}

/// The order-0 size of `bytes`, in sixteenths of a bit: the sum over
/// byte values of `count * (log2(total) - log2(count))`, in the integer
/// log the encoder prices with, so no platform's `log2` can move it. The
/// cheap test the pre-screen puts a stage one delta through: a delta whose
/// output is not smaller byte for byte than the input is not worth an LZ
/// probe. (A whole Huffman build here cost more than the rest of the
/// screen together on a region where nothing fires.)
fn order0_bits(bytes: impl Iterator<Item = u8>) -> u64 {
    let mut counts = [0u32; 256];
    for byte in bytes {
        counts[byte as usize] += 1;
    }
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    if total == 0 {
        return 0;
    }
    let log_total = u64::from(log2_sixteenths(total));
    counts
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| u64::from(c) * (log_total - u64::from(log2_sixteenths(u64::from(c)))))
        .sum()
}

/// How many positions of `a` hold the byte `b` holds there, over the
/// shorter of the two. Summed in sixteen byte lanes, emptied before one
/// can overflow, which is the form the compiler turns into sixteen
/// compares an instruction:
/// this count, 32 lags over a 16 KiB window, is most of what the screen
/// costs a region where nothing fires.
fn equal_bytes(a: &[u8], b: &[u8]) -> usize {
    count_lanes(a, b, |x, y| x == y)
}

/// How many positions `i` of the shorter of `a` and `b` satisfy
/// `holds(a[i], b[i])`, counted in sixteen byte lanes (see
/// [`equal_bytes`]).
#[inline(always)]
fn count_lanes(a: &[u8], b: &[u8], holds: impl Fn(u8, u8) -> bool) -> usize {
    let n = a.len().min(b.len());
    let (a, a_tail) = a[..n].as_chunks::<16>();
    let (b, b_tail) = b[..n].as_chunks::<16>();
    let mut total = 0;
    // Sixteen byte lanes, emptied every 255 steps so none can overflow.
    for (a, b) in a.chunks(255).zip(b.chunks(255)) {
        let mut lanes = [0u8; 16];
        for (x, y) in a.iter().zip(b) {
            for ((lane, &p), &q) in lanes.iter_mut().zip(x).zip(y) {
                *lane += u8::from(holds(p, q));
            }
        }
        total += lanes.iter().map(|&lane| usize::from(lane)).sum::<usize>();
    }
    total
        + a_tail
            .iter()
            .zip(b_tail)
            .filter(|(&x, &y)| holds(x, y))
            .count()
}

/// Whether lag `lag`'s count stands out among `counts` over a window of
/// `len` bytes (see [`lags`]).
fn stands_out(counts: &[usize; LAGS + 1], lag: usize, len: usize) -> bool {
    let sum: usize = counts.iter().sum();
    counts[lag] * LAGS * 2 > sum * LAG_OVER_MEAN_HALVES && counts[lag] * LAG_LEAST_SHARE >= len
}

/// The (at most two) lags [`lags`] picks from `counts`.
fn picked_lags(counts: &[usize; LAGS + 1], len: usize) -> [Option<u8>; 2] {
    let stands_out = |count: usize| {
        let sum: usize = counts.iter().sum();
        count * LAGS * 2 > sum * LAG_OVER_MEAN_HALVES && count * LAG_LEAST_SHARE >= len
    };
    let mut picked: [Option<u8>; 2] = [None, None];
    for index in 0..picked.len() {
        let mut best: Option<(usize, usize)> = None;
        for (lag, &count) in counts.iter().enumerate().skip(3) {
            if lag == 4 || picked.contains(&Some(lag as u8)) || !stands_out(count) {
                continue;
            }
            if best.is_none_or(|(_, most)| count > most) {
                best = Some((lag, count));
            }
        }
        picked[index] = best.map(|(lag, _)| lag as u8);
    }
    picked
}

/// What the pre-screen admits into stage one, from counts that cost a
/// pass over the probe windows and no coding.
///
/// Shipped 27 Sep 2026, on these
/// untimed figures from an Apple M3 Mac (detection alone, one thread): text 9.37 to
/// 0.69 ns a byte, noise 11.5 to 0.45, zlib 13.8 to 0.45, archives
/// identical; libLLVM 14.9 to 6.3 (arm64) and 14.2 to 6.1 (x86-64), at
/// 0.53 and 0.39 per cent larger than full probing.
struct Screen {
    /// Deltas of 1, 2 and 4: their lag stands out in the front window.
    deltas: [bool; 3],
    /// x86: enough E8/E9 bytes whose next four read as a near
    /// displacement (top byte 0x00 or 0xff), at least one in
    /// [`X86_SCREEN_SHARE`] bytes of the windows.
    x86: bool,
    /// ARM: enough words ending 0xEB, at least one in [`ARM_SCREEN_SHARE`].
    arm: bool,
    /// The lag screen's picks that pass the order-0 test.
    lags: [Option<u8>; 2],
}

/// One plausible x86 call operand in this many window bytes admits x86.
const X86_SCREEN_SHARE: usize = 512;
/// One BL-shaped word in this many admits ARM.
const ARM_SCREEN_SHARE: usize = 64;

impl Screen {
    fn of(
        region: &[u8],
        windows: &[std::ops::Range<usize>],
        front: usize,
        counts: &[usize; LAGS + 1],
    ) -> Screen {
        let mut plausible = 0;
        let mut bl = 0;
        let mut words = 0;
        let mut bytes = 0;
        for window in windows {
            let w = &region[window.clone()];
            bytes += w.len();
            if w.len() > 4 {
                plausible += count_lanes(&w[..w.len() - 4], &w[4..], |opcode, top| {
                    opcode & 0xfe == 0xe8 && (top == 0x00 || top == 0xff)
                });
            }
            // Word boundaries from the region's start, as the transform
            // takes them.
            let first = window.start.next_multiple_of(4) - window.start;
            for word in w[first.min(w.len())..].as_chunks::<4>().0 {
                words += 1;
                bl += usize::from(word[3] == 0xeb);
            }
        }
        let window = &region[windows[0].clone()];
        let plain = order0_bits(window.iter().copied());
        Screen {
            deltas: [1usize, 2, 4]
                .map(|lag| stands_out(counts, lag, front) && delta_shrinks(window, lag, plain)),
            x86: plausible * X86_SCREEN_SHARE >= bytes && plausible > 0 && !no_x86(),
            arm: bl * ARM_SCREEN_SHARE >= words && bl > 0,
            // The lag screen's picks, put through the same order-0 test:
            // indentation stands a lag out in source text, and a delta of
            // it does not shrink a byte.
            lags: picked_lags(counts, front)
                .map(|lag| lag.filter(|&lag| delta_shrinks(window, usize::from(lag), plain))),
        }
    }

    fn admits(&self, kind: FilterKind) -> bool {
        match kind {
            FilterKind::Delta(1) => self.deltas[0],
            FilterKind::Delta(2) => self.deltas[1],
            FilterKind::Delta(4) => self.deltas[2],
            FilterKind::X86CallJump | FilterKind::X86Call => self.x86,
            FilterKind::Arm => self.arm,
            FilterKind::Delta(_) => true,
        }
    }

    fn empty(&self) -> bool {
        !self.deltas.iter().any(|&d| d) && !self.x86 && !self.arm && self.lags == [None, None]
    }
}

/// Whether the pre-screen runs: always in a shipped build (decided
/// 27 Sep 2026), and in a bench build unless
/// `RARKIT_FILTER_SCREEN=full` asks for full probing, which is kept as the
/// record the screen is measured against.
fn screened() -> bool {
    #[cfg(feature = "bench-internals")]
    {
        static SCREENED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *SCREENED
            .get_or_init(|| std::env::var("RARKIT_FILTER_SCREEN").map_or(true, |v| v != "full"))
    }
    #[cfg(not(feature = "bench-internals"))]
    true
}

/// Whether stage two after a delta win probes only the lag screen's picks
/// rather than the whole stride list: always in a shipped build
/// (decided 27 Sep 2026, on archives identical
/// over all eight counted corpora for two to three times fewer detection
/// instructions on 16-bit audio and RGBA), and in a bench build unless
/// `RARKIT_FILTER_WIDE=list` asks for the list, which is kept as the
/// record.
fn narrow_stage_two() -> bool {
    #[cfg(feature = "bench-internals")]
    {
        static NARROW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *NARROW.get_or_init(|| std::env::var("RARKIT_FILTER_WIDE").map_or(true, |v| v != "list"))
    }
    #[cfg(not(feature = "bench-internals"))]
    true
}

/// Whether detection never admits the x86 transforms
/// (`RARKIT_FILTER_NO_X86=1`, a bench build only): the diagnosis of what
/// they buy on a whole library.
fn no_x86() -> bool {
    #[cfg(feature = "bench-internals")]
    {
        static NO_X86: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *NO_X86.get_or_init(|| std::env::var("RARKIT_FILTER_NO_X86").is_ok_and(|v| v == "1"))
    }
    #[cfg(not(feature = "bench-internals"))]
    false
}

/// What the estimate may take at one position (spec G section 3.8.2,
/// "The offer").
enum Offer {
    /// The byte is counted as itself.
    Nothing,
    /// A copy at the distance of the copy before.
    Repeat { length: usize },
    /// A copy from the table's place, at a distance of its own.
    NewCopy { length: usize, distance: usize },
}

/// The table's place for the four bytes at `at`: the top 12 bits of
/// their little endian value times Knuth's 32 bit multiplier.
#[inline]
fn slot(window: &[u8], at: usize) -> usize {
    let key = u32::from_le_bytes([window[at], window[at + 1], window[at + 2], window[at + 3]]);
    (key.wrapping_mul(2_654_435_761) >> (32 - PLACES.trailing_zeros())) as usize
}

/// The count of binary digits of `value`, which is at least 1.
fn digits(value: usize) -> u64 {
    u64::from(usize::BITS - value.leading_zeros())
}

/// The fixed charge for a length: `2 * digits - 1` bits.
fn gamma(value: usize) -> u64 {
    2 * digits(value) - 1
}

/// The bits one of `count` equal symbols is charged among `total`: the
/// smallest `l` with `count * 2^l >= total`, from 1 to
/// [`LONGEST_CHARGE`]. No code is built.
fn charge(count: u32, total: u64) -> u64 {
    let enough = |l: &u32| u64::from(count) << l >= total;
    u64::from((1..LONGEST_CHARGE).find(enough).unwrap_or(LONGEST_CHARGE))
}

/// How many bytes at `from` equal those at `at`, up to `limit`, a word at
/// a time (the carried tree's own compare).
#[inline]
fn common(window: &[u8], from: usize, at: usize, limit: usize) -> usize {
    common_prefix(window, from, at, 0, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(seed: u64) -> impl FnMut() -> u32 {
        let mut state = seed;
        move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
        }
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut next = rng(7);
        (0..len).map(|_| next() as u8).collect()
    }

    /// Interleaved PCM of `channels` channels of `width` bytes, slow
    /// tones with a noisy low byte.
    fn pcm(len: usize, channels: usize, width: usize) -> Vec<u8> {
        let mut next = rng(11);
        let mut out = Vec::new();
        let mut n = 0i64;
        while out.len() < len {
            for c in 0..channels as i64 {
                let phase = (n * (3 + 2 * c)) % 4096;
                let triangle = if phase < 2048 { phase } else { 4096 - phase };
                let top = (triangle - 1024) << (8 * width - 12);
                let sample = top + i64::from(next() % 256) - 128;
                out.extend_from_slice(&sample.to_le_bytes()[..width]);
            }
            n += 1;
        }
        out.truncate(len);
        out
    }

    fn screen_of(region: &[u8]) -> Screen {
        let (windows, count) = windows(region.len());
        let front = &region[windows[0].clone()];
        Screen::of(region, &windows[..count], front.len(), &lag_counts(front))
    }

    #[test]
    fn the_screen_admits_nothing_where_no_filter_can_pay() {
        assert!(screen_of(&noise(MAX_SPAN)).empty(), "noise");
        assert!(
            screen_of(&rarkit_testdata::chatter(0x6669_6c74, MAX_SPAN)).empty(),
            "text"
        );
        let mut probe = Probe::new();
        assert_eq!(probe.judge(&noise(MAX_SPAN), 0), None);
        assert_eq!(
            probe.judge(&rarkit_testdata::chatter(0x6669_6c74, MAX_SPAN), 0),
            None
        );
    }

    #[test]
    fn the_lag_screen_finds_the_frame_of_wide_audio() {
        let stereo24 = pcm(PROBE_BYTES, 2, 3);
        assert_eq!(lags(&stereo24)[0], Some(6), "24-bit stereo");
        let six16 = pcm(PROBE_BYTES, 6, 2);
        assert_eq!(lags(&six16)[0], Some(12), "six channels of 16 bits");
        assert_eq!(
            lags(&rarkit_testdata::chatter(0x6669_6c74, PROBE_BYTES)),
            [None, None],
            "text"
        );
    }

    #[test]
    fn wide_audio_is_judged_a_delta_of_its_frame() {
        let mut probe = Probe::new();
        assert_eq!(
            probe.judge(&pcm(MAX_SPAN, 2, 3), 0),
            Some(FilterKind::Delta(6))
        );
        assert_eq!(
            probe.judge(&pcm(MAX_SPAN, 6, 2), 0),
            Some(FilterKind::Delta(12))
        );
    }

    #[test]
    fn a_filter_must_beat_the_unfiltered_probe_by_more_than_two_per_cent() {
        assert!(!keeps(98, 100), "exactly 2 per cent is a tie");
        assert!(keeps(97, 100));
        assert!(!keeps(100, 100));
    }

    #[test]
    fn a_plan_is_ascending_disjoint_and_inside_its_bytes() {
        let mut bytes = pcm(3 << 20, 2, 2);
        bytes.extend(noise(1 << 20));
        let mut plan = Vec::new();
        detect(&bytes, 0, &mut plan);
        assert!(!plan.is_empty());
        let mut end = 0;
        for span in &plan {
            assert!(span.start >= end && span.len <= MAX_SPAN);
            assert_eq!(span.start % PARSE_BLOCK_BYTES, 0);
            end = span.start + span.len;
        }
        assert!(end <= bytes.len());
    }

    /// The generator of spec G section 3.8.2's last two hand vectors.
    fn generated(len: usize) -> Vec<u8> {
        let mut x = 1u64;
        let step = |_| {
            x = (x * 1_103_515_245 + 12_345) % (1 << 31);
            (x >> 16) as u8
        };
        (0..len).map(step).collect()
    }

    /// Spec G section 3.8.2's eight hand vectors of the price. Each runs
    /// on the calling thread alone, with no pool, in the probe's own
    /// buffers (under 100 KiB) and a window of 2,000 bytes at most.
    fn priced(window: &[u8]) -> u64 {
        Probe::new().cost(window)
    }

    #[test]
    fn g_3_8_2_price_of_the_empty_window() {
        assert_eq!(priced(&[]), 0);
    }

    #[test]
    fn g_3_8_2_price_of_three_bytes_too_short_for_an_offer() {
        assert_eq!(priced(b"abc"), 6);
    }

    #[test]
    fn g_3_8_2_price_of_one_byte_eight_times_a_copy_over_itself() {
        assert_eq!(priced(&[0x61; 8]), 12);
    }

    #[test]
    fn g_3_8_2_price_of_the_256_byte_values_in_order() {
        let window: Vec<u8> = (0..=255).collect();
        assert_eq!(priced(&window), 2_048);
    }

    #[test]
    fn g_3_8_2_price_of_four_bytes_64_times_over() {
        assert_eq!(priced(&b"abcd".repeat(64)), 37);
    }

    #[test]
    fn g_3_8_2_price_with_both_kinds_of_copy_and_a_tie_the_repeat_wins() {
        assert_eq!(priced(b"abcdexabcdeyzbcdeabc"), 59);
    }

    #[test]
    fn g_3_8_2_price_of_1000_generated_bytes() {
        assert_eq!(priced(&generated(1_000)), 8_156);
    }

    #[test]
    fn g_3_8_2_price_of_the_1000_generated_bytes_twice_over() {
        assert_eq!(priced(&generated(1_000).repeat(2)), 8_199);
    }

    /// The price is of the window alone: a probe that priced other bytes
    /// before gives the same number as a new one. Calling thread only,
    /// no pool, 16 KiB of window.
    #[test]
    fn g_3_8_2_price_does_not_depend_on_an_earlier_call() {
        let window = rarkit_testdata::chatter(0x6669_6c74, PROBE_BYTES);
        let mut probe = Probe::new();
        probe.cost(&noise(PROBE_BYTES));
        assert_eq!(probe.cost(&window), priced(&window));
    }

    /// The stamped table ([`Probe::base`]) prices a window as a table
    /// filled for it alone would: a probe that priced hundreds of windows
    /// of every size before, small members' and a full window's, and one
    /// whose stamps run out part way, give each window the number a new
    /// probe gives it. Calling thread only, no pool, under 1 MiB.
    #[test]
    fn g_3_8_2_price_is_the_same_through_many_windows_and_a_stamp_roll_over() {
        let text = rarkit_testdata::chatter(0x7374_616d, 64 << 10);
        let mixed = [text.clone(), noise(64 << 10), pcm(64 << 10, 2, 2)].concat();
        let mut next = rng(19);
        let mut probe = Probe::new();
        for round in 0..400 {
            let len = match round % 4 {
                0 => 4 + next() as usize % 60,
                1 => 300 + next() as usize % 3_000,
                2 => PROBE_BYTES,
                _ => next() as usize % 9_000,
            };
            let at = next() as usize % (mixed.len() - len);
            let window = &mixed[at..at + len];
            if round == 200 {
                // Close enough to the end of the stamps that this window
                // and the next run them out.
                probe.next = NO_POSITION - 20_000;
            }
            assert_eq!(
                probe.cost(window),
                Probe::new().cost(window),
                "round {round}"
            );
        }
        assert!(probe.next < 1 << 30, "the stamps rolled over");
    }
}
