//! The probe: a device's write rate judged over a window, and the verdict
//! remembered per device.

use super::*;

/// The rate, in bytes a second, below which the gate finds a device SLOW
/// and an output leaves direct writing for the cached path.
pub(crate) const GATE_RATE: u64 = 1_500_000_000;

/// The probe's SPAN: the first bytes of an output written past the cache
/// that the gate times, at most, judged by their SUSTAINED rate, the bytes
/// over the time the direct writes took ([`judge`]). SLOW as soon as that
/// time exceeds what the whole span takes at [`GATE_RATE`] (716 ms): the
/// span can no longer reach the rate, however fast the rest goes. FAST once
/// the span has landed inside that time.
///
/// Not a short window, nor a majority of chunks or writes: a device can take
/// a burst far above its rate (a drive's write cache, an SSD's SLC cache, a
/// throttle's budget: on a 200 MB/s device the first 8 MiB went at 4 to
/// 9 GB/s, and a throttle passes most writes at once and holds the next),
/// and a fast disk can stall (an NVMe on Windows ran 243 MB at 405 MB/s
/// straight after another 12.9 GB write, then 11 GB/s again). Over 1 GiB a
/// burst is a small part of the span, and an 11 GB/s disk may stall about
/// 620 ms in all (a 2.2 GB/s one about 230 ms) and still be found fast.
/// The price on a slow disk is at most 716 ms of direct writing, and one
/// write, before the output goes cached.
pub(crate) const SPAN: u64 = 1 << 30;

/// What the gate found a device to be.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Verdict {
    /// At or above [`GATE_RATE`]: direct writing stays.
    Fast,
    /// Below it: the cached path, from the probe's last write on.
    Slow,
}

/// Where the write-rate gate stands for one output.
pub(super) enum Gate {
    /// Timed by the probe of its device, shared with every other output
    /// writing there, until that probe has a verdict.
    Probing(std::sync::Arc<Probe>),
    /// Judged or remembered fast, or not gated (`RARFAST_DIRECT=on`).
    Open,
    /// Judged or remembered slow: the next put falls back.
    Shut,
}

/// ONE DEVICE'S PROBE,
/// shared by every output writing past the cache to it, and its verdict for
/// the rest of the process.
///
/// Before, each output timed its OWN writes, summing their
/// durations. A stored volume set's split members go to the pool and four to
/// six of them write to one drive at once, so each output saw its share of
/// the drive: on a Zen 4 rental a 3,410 MiB/s NVMe read 690 MB/s an output, was
/// found slow by the first to judge, and the whole set fell back to cached
/// writes, 1.295x slower on disk than direct (1 Oct 2026).
/// Now the bytes are EVERY output's direct bytes to the
/// device, over the device's BUSY WALL: the time during which at least one
/// direct write to it was in flight, however many were. Not the wall from the
/// first write: a compressed member hands its bytes over at the decoder's
/// pace, and the device idle between them is not the device being slow.
pub(crate) struct Probe {
    pub(super) state: std::sync::Mutex<Probed>,
    /// For ONE OUTPUT's own probe (`RARFAST_PROBE=own`, a measuring arm): the
    /// device's, which takes this one's verdict if it has none yet.
    pub(super) device: Option<std::sync::Arc<Probe>>,
}

/// Whether every output on a device is timed by the device's one probe: on
/// every target.
///
/// Windows kept each output timing its own writes for this change's first two
/// versions, until its rows were in. On a Windows desktop's stored set (eight 1.1 GiB
/// members written several at once, depth 1, warm, on disk, K=3) the
/// per-output probe said SLOW in every rep, each output seeing its share of
/// the drive (3.40, 11.01 and 5.37 s on disk), and the device's one probe
/// said FAST in every rep (3.24, 3.11, 3.23 s; the parent 3.53, UnRAR 6.63).
pub(super) const SHARED_PROBE: bool = true;

/// [`SHARED_PROBE`], or in a `reserve-knob` build what `RARFAST_PROBE` says
/// (`shared`, `own`), so one binary times both.
pub(super) fn shared_probe() -> bool {
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static SET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *SET.get_or_init(|| {
            let shared = match std::env::var("RARFAST_PROBE").unwrap_or_default().trim() {
                "shared" => true,
                "own" => false,
                _ => SHARED_PROBE,
            };
            eprintln!("rarfast probe shared: {shared}");
            shared
        })
    }
    #[cfg(not(all(not(test), feature = "reserve-knob")))]
    {
        SHARED_PROBE
    }
}

/// A probe's count so far.
#[derive(Default)]
pub(super) struct Probed {
    pub(super) verdict: Option<Verdict>,
    /// Bytes landed by timed direct writes.
    pub(super) bytes: u64,
    /// Busy time already closed: spans with a write in flight.
    pub(super) busy: Duration,
    /// When the device last went from idle to busy, while it is busy.
    pub(super) since: Option<Instant>,
    /// Timed writes in flight.
    pub(super) writing: u32,
}

impl Probe {
    pub(super) fn new() -> Probe {
        Probe {
            state: std::sync::Mutex::new(Probed::default()),
            device: None,
        }
    }

    pub(super) fn state(&self) -> std::sync::MutexGuard<'_, Probed> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The device's verdict, once [`judge`] has given one.
    pub(crate) fn verdict(&self) -> Option<Verdict> {
        self.state().verdict
    }

    /// A timed write begins.
    pub(super) fn start(&self) {
        let mut state = self.state();
        if state.writing == 0 {
            state.since = Some(Instant::now());
        }
        state.writing += 1;
    }

    /// A timed write ended, `bytes` of it landed (0 for a failed one): the
    /// busy wall so far is judged, and the first verdict stands.
    pub(super) fn end(&self, bytes: u64) {
        let mut state = self.state();
        let now = Instant::now();
        state.writing = state.writing.saturating_sub(1);
        state.bytes += bytes;
        let took = state.busy + state.since.map_or(Duration::ZERO, |since| now - since);
        if state.writing == 0 {
            state.busy = took;
            state.since = None;
        }
        if state.verdict.is_some() {
            return;
        }
        let verdict = if forced() == Forced::Slow {
            Some(Verdict::Slow)
        } else {
            judge(state.bytes, took, gate_rate())
        };
        let Some(verdict) = verdict else {
            return;
        };
        #[cfg(all(not(test), feature = "reserve-knob"))]
        {
            eprintln!(
                "rarfast gate: {verdict:?} after {} bytes in {} us busy ({} MB/s; gate {} MB/s)",
                state.bytes,
                took.as_micros(),
                (state.bytes as u128 * 1_000_000 / took.as_nanos().max(1)) / 1_000,
                gate_rate() / 1_000_000,
            );
        }
        state.verdict = Some(verdict);
        if let Some(device) = &self.device {
            device.state().verdict.get_or_insert(verdict);
        }
    }
}

/// Whether one direct write of `bytes` in `took` ran at or above `rate`
/// bytes a second. A `rate` of 0 finds every write fast (a test build: its
/// outputs are never found slow by a loaded runner's timing, only by
/// [`Forced::Slow`]).
pub(crate) fn at_rate(bytes: u64, took: Duration, rate: u64) -> bool {
    u128::from(bytes) * 1_000_000_000 >= took.as_nanos() * u128::from(rate)
}

/// The gate's verdict once `bytes` of the span have landed in `took`,
/// against `rate` bytes a second; `None` while the span must go on (see
/// [`SPAN`]).
pub(crate) fn judge(bytes: u64, took: Duration, rate: u64) -> Option<Verdict> {
    if !at_rate(SPAN, took, rate) {
        Some(Verdict::Slow)
    } else if bytes >= SPAN {
        Some(Verdict::Fast)
    } else {
        None
    }
}

/// The gate's rate: [`GATE_RATE`] as shipped; 0 in a test build (see
/// [`at_rate`]); and in a `reserve-knob` build, `RARFAST_GATE_MBPS` in
/// decimal megabytes a second where it is set, so one binary times several
/// gates.
pub(super) fn gate_rate() -> u64 {
    #[cfg(test)]
    {
        0
    }
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static RATE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *RATE.get_or_init(|| {
            std::env::var("RARFAST_GATE_MBPS")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map_or(GATE_RATE, |mbps| mbps * 1_000_000)
        })
    }
    #[cfg(all(not(test), not(feature = "reserve-knob")))]
    {
        GATE_RATE
    }
}

/// The device `file` (at `path`) lives on, as a key for the gate's memo:
/// its `st_dev` on Unix; on Windows, whose standard library names no
/// volume for a handle, the drive or share at the head of the absolute
/// path (a volume mounted in a folder shares its parent's verdict).
#[cfg(unix)]
pub(super) fn device_of(_path: &Path, file: &File) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    file.metadata().ok().map(|m| m.dev())
}

/// See the Unix [`device_of`].
#[cfg(not(unix))]
pub(super) fn device_of(path: &Path, _file: &File) -> Option<u64> {
    device_at(path)
}

/// The device the existing `path` (a file or a directory) lives on, by the
/// same key as [`device_of`].
#[cfg(unix)]
pub(crate) fn device_at(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.dev())
}

/// See the Unix [`device_at`].
#[cfg(windows)]
pub(crate) fn device_at(path: &Path) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    let absolute = std::path::absolute(path).ok()?;
    let std::path::Component::Prefix(prefix) = absolute.components().next()? else {
        return None;
    };
    let mut hasher = std::hash::DefaultHasher::new();
    prefix
        .as_os_str()
        .to_string_lossy()
        .to_lowercase()
        .hash(&mut hasher);
    Some(hasher.finish())
}

/// See the Unix [`device_at`].
#[cfg(not(any(unix, windows)))]
pub(crate) fn device_at(_path: &Path) -> Option<u64> {
    None
}

/// The gate's memo: each device's probe, and so its verdict, for the rest
/// of the process. A test build keeps one per THREAD (the thread that
/// creates the output; its writer thread holds the probe itself), so a test
/// that forces a slow verdict never shuts the gate for another test's
/// output on the same disk.
pub(super) type Memo = Vec<(u64, std::sync::Arc<Probe>)>;

#[cfg(not(test))]
pub(super) static MEMO: std::sync::Mutex<Memo> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
thread_local! {
    pub(super) static MEMO: std::cell::RefCell<Memo> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Runs `f` on the memo.
pub(super) fn with_memo<R>(f: impl FnOnce(&mut Memo) -> R) -> R {
    #[cfg(not(test))]
    {
        f(&mut MEMO.lock().unwrap_or_else(|p| p.into_inner()))
    }
    #[cfg(test)]
    {
        MEMO.with(|memo| f(&mut memo.borrow_mut()))
    }
}

/// The probe of `device`, made on its first output; a device that cannot
/// be named gets one of its own, never remembered, so it is probed every
/// time.
pub(super) fn probe_for(device: Option<u64>) -> std::sync::Arc<Probe> {
    let Some(device) = device else {
        return std::sync::Arc::new(Probe::new());
    };
    with_memo(|memo| {
        if let Some((_, probe)) = memo.iter().find(|(d, _)| *d == device) {
            return probe.clone();
        }
        let probe = std::sync::Arc::new(Probe::new());
        memo.push((device, probe.clone()));
        probe
    })
}

/// The verdict remembered for `device`, if any.
pub(crate) fn remembered(device: Option<u64>) -> Option<Verdict> {
    let device = device?;
    with_memo(|memo| {
        memo.iter()
            .find(|(d, _)| *d == device)
            .and_then(|(_, probe)| probe.verdict())
    })
}

/// Remembers `verdict` for `device`, for a test; the first verdict for a
/// device stands.
#[cfg(test)]
pub(super) fn remember(device: Option<u64>, verdict: Verdict) {
    if device.is_some() {
        probe_for(device).state().verdict.get_or_insert(verdict);
    }
}

/// Forgets every verdict, for a test.
#[cfg(test)]
pub(crate) fn forget() {
    with_memo(Vec::clear);
}
