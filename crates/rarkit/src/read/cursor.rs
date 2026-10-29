//! One forward pass over a source through one buffer (spec F 2.1, 7.3.1).
//!
//! Header bytes are read in blocks of at least 4 KiB where the source has
//! them, never one read per field, and the walk never seeks backwards. A
//! jump forward over a data area advances inside the buffer when the bytes
//! are already there and costs one read when they are not: one read per
//! data area, never one per header.

use std::sync::Arc;

use crate::error::{Error, ErrorKind, Result};
use crate::memory;
use crate::source::RangeSource;

/// The smallest read this cursor ever issues (API section 5.1).
pub(crate) const MIN_READ: usize = 4096;

/// The widest window a run of short forward refills can grow to.
const READ_AHEAD_CAP: usize = 64 * 1024;

/// A refill counts toward a run when it lands no further than this past
/// the previous one.
const CLOSE_STEP: u64 = 16 * 1024;

/// Refills in a run before the window grows to its read-ahead allowance.
const RUN_TO_GROW: u8 = 3;

/// Read exactly `buf.len()` bytes at `offset`. A source that ends first is
/// [`ErrorKind::Truncated`]; a source error is [`ErrorKind::Source`].
pub(crate) fn read_exact_at(src: &dyn RangeSource, at: u64, buf: &mut [u8]) -> Result<()> {
    let got = read_upto_at(src, at, buf)?;
    if got == buf.len() {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Truncated).with_offset(at + got as u64))
    }
}

/// Fill as much of `buf` as the source has at `offset`, looping over short
/// reads. Returns how many bytes landed; fewer than `buf.len()` means the
/// source ended.
pub(crate) fn read_upto_at(src: &dyn RangeSource, at: u64, buf: &mut [u8]) -> Result<usize> {
    #[cfg(feature = "parallel")]
    if buf.len() >= deep::FLOOR {
        let parts = deep::PARTS.with(std::cell::Cell::get);
        if parts > 1 {
            return deep::read_split(src, at, buf, parts);
        }
    }
    read_serial(src, at, buf)
}

/// [`read_upto_at`] as one read on the calling thread.
fn read_serial(src: &dyn RangeSource, at: u64, buf: &mut [u8]) -> Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        let offset = at + done as u64;
        match src.read_at(offset, &mut buf[done..]) {
            Ok(0) => break,
            // A source that claims more than it was given cannot be allowed
            // to make the caller read uninitialised bytes.
            Ok(n) => done += n.min(buf.len() - done),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::new(ErrorKind::Source(e)).with_offset(offset)),
        }
    }
    Ok(done)
}

/// READ DEPTH for a reader that asks for one big range at a time and
/// waits for it: the LZ decoder's packed fills (`read::extract`'s
/// `Buffered`), each up to 4 MiB, read on the thread that decodes.
///
/// **Why.** One read in order keeps only the kernel's read-ahead in flight
/// on a cold file, and on Linux that is a window of 256 KiB to 512 KiB, so
/// the decoder waits on the drive at every fill. Cut into a few concurrent
/// reads of page-aligned parts, one fill keeps several requests in flight.
/// On a Zen 4 rental (PM9A3-class NVMe) S8's cold `t` went 1.108x faster at
/// four parts and its cold `x` 1.104x (1.146x at eight), warm level
/// (measured 30 Sep 2026). On macOS the same
/// split halved a cold extract (two reads of 2 MiB are no longer the
/// stream the kernel reads ahead for), so it is Linux's alone.
///
/// **Scoped to its caller.** A reader opts in for the length of one call
/// with [`deep::deeply`]; every other read of the engine (headers, the
/// wide read's pieces, the seam's slabs, the stored copy) is one read on
/// its own thread as before, whatever its size. The bytes, their order and
/// every error and offset reported are the single read's: parts are
/// joined in order, and the bytes landed are the prefix up to the first
/// part that came back short.
#[cfg(feature = "parallel")]
pub(crate) mod deep {
    use std::cell::Cell;

    use super::read_serial;
    use crate::error::Result;
    use crate::source::RangeSource;

    /// The smallest read that is split: a fill below it is a member's
    /// tail or a small member, where a thread costs more than the depth.
    pub(crate) const FLOOR: usize = 2 << 20;

    /// The page every part but the last is a whole number of.
    const PAGE: usize = 4096;

    /// The parts a fill is cut into where the width allows them: four on
    /// Linux, one (no split) everywhere else.
    #[cfg(target_os = "linux")]
    const SHIPPED: usize = 4;
    #[cfg(not(target_os = "linux"))]
    const SHIPPED: usize = 1;

    thread_local! {
        /// The parts a read of [`FLOOR`] and up on this thread is cut
        /// into; 1 outside [`deeply`].
        pub(super) static PARTS: Cell<usize> = const { Cell::new(1) };
    }

    /// The parts a reader granted `width` lanes cuts its fills into:
    /// [`SHIPPED`], never more than the width, so `-mt1` reads on one
    /// thread.
    ///
    /// A count-only knob (feature `read-depth-knob`, never shipped):
    /// `RARKIT_SPLIT_READS`, read once, replaces [`SHIPPED`] on every
    /// system, 1 being the single read before this lever.
    pub(crate) fn parts(width: usize) -> usize {
        target().min(width.max(1))
    }

    #[cfg(feature = "read-depth-knob")]
    fn target() -> usize {
        static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *N.get_or_init(|| {
            std::env::var("RARKIT_SPLIT_READS")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .filter(|&n: &usize| (1..=64).contains(&n))
                .unwrap_or(SHIPPED)
        })
    }

    #[cfg(not(feature = "read-depth-knob"))]
    #[inline(always)]
    fn target() -> usize {
        SHIPPED
    }

    /// Run `f` with this thread's big reads cut into `parts`; the setting
    /// before is restored after, a panic included.
    pub(crate) fn deeply<T>(parts: usize, f: impl FnOnce() -> T) -> T {
        struct Restore(usize);
        impl Drop for Restore {
            fn drop(&mut self) {
                let before = self.0;
                PARTS.with(|p| p.set(before));
            }
        }
        let _restore = Restore(PARTS.with(|p| p.replace(parts.max(1))));
        f()
    }

    /// One read cut into `parts` page-aligned parts, the first read on the
    /// calling thread and the rest on scoped threads, joined in order.
    pub(super) fn read_split(
        src: &dyn RangeSource,
        at: u64,
        buf: &mut [u8],
        parts: usize,
    ) -> Result<usize> {
        let part = buf.len().div_ceil(parts).next_multiple_of(PAGE);
        let got: Vec<(usize, Result<usize>)> = std::thread::scope(|s| {
            let mut chunks = buf.chunks_mut(part).enumerate();
            let (_, first) = chunks.next().expect("a split read has a first part");
            let rest: Vec<_> = chunks
                .map(|(i, c)| {
                    let len = c.len();
                    let off = at + (i * part) as u64;
                    (len, s.spawn(move || read_serial(src, off, c)))
                })
                .collect();
            let len = first.len();
            let mut out = vec![(len, read_serial(src, at, first))];
            out.extend(rest.into_iter().map(|(len, h)| {
                (
                    len,
                    h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
                )
            }));
            out
        });
        let mut done = 0usize;
        for (len, r) in got {
            let g = r?;
            done += g;
            if g < len {
                break;
            }
        }
        Ok(done)
    }
}

/// How a walk holds the source it reads: borrowed, which is what a walk
/// bounded by one call needs, or shared, which is what the volume walk of
/// spec F 2.3 needs. A walk that continues one member across a volume
/// boundary outlives the local the volume provider handed over, so it
/// keeps the `Arc` alive itself rather than borrowing a caller's local.
pub(crate) enum Handle<'s> {
    Borrowed(&'s dyn RangeSource),
    Shared(Arc<dyn RangeSource>),
}

impl Handle<'_> {
    #[inline]
    fn get(&self) -> &dyn RangeSource {
        match self {
            Handle::Borrowed(src) => *src,
            Handle::Shared(src) => src.as_ref(),
        }
    }
}

/// A forward window onto a source.
///
/// The live bytes are `buf[start..end]`, and `base` is the source offset of
/// `buf[start]` rather than of `buf[0]`. That indirection is the whole
/// point: a forward step moves `start`, which costs nothing, where forcing
/// the live bytes back to `buf[0]` on every step costs the WINDOW per step.
///
/// Measured before this was so, on `f/test-rar4-20000-vsnull` (20,000 RAR 4
/// members of about 152 bytes): `_platform_memmove` was 43.9% of the
/// extract arm's self time and 41.2% of a walk that decodes nothing, and
/// the leg moved about 40.9 MB to read a 4.27 MB archive, a factor of 9.6.
/// The window is [`MIN_READ`] and drained over about nineteen members, so
/// each step slid half a window.
///
/// Bytes now move only to make room for a read that will not fit in the
/// tail, so the moving is bounded by the bytes READ rather than by the
/// steps taken, which is what
/// `tests::a_forward_walk_slides_far_less_than_it_reads` pins.
pub(crate) struct Cursor<'s> {
    src: Handle<'s>,
    buf: Vec<u8>,
    /// Source offset of `buf[start]`.
    base: u64,
    /// First live byte in `buf`.
    start: usize,
    /// One past the last live byte in `buf`.
    end: usize,
    /// Bytes charged to the process-wide counter for `buf`.
    charged: u64,
    /// Source offset of the previous refill, and how many refills in a
    /// row have each landed a short step forward of the one before.
    last_fill: u64,
    run: u8,
    /// How wide a run may grow the window: [`MIN_READ`] (never grows)
    /// unless the walk that owns the cursor grants more.
    ahead: usize,
    /// The largest `available()` answer seen, which only ever grows, so
    /// the source is asked again only when a wide read would pass it.
    avail: u64,
    /// Bytes slid by a compaction, which only the test that pins the
    /// amortisation reads. `cfg(test)` so the shipped cursor carries
    /// neither the counter nor its update.
    #[cfg(test)]
    moved: u64,
}

/// An encrypted header is read through the window, exactly as a clear
/// one is peeked.
impl crate::crypto::header::HeaderBytes for Cursor<'_> {
    fn read_exact_at(&mut self, at: u64, buf: &mut [u8]) -> Result<()> {
        let bytes = self.peek(at, buf.len())?;
        buf.copy_from_slice(bytes);
        Ok(())
    }
}

impl<'s> Cursor<'s> {
    /// A cursor over `src` whose buffer starts empty.
    pub(crate) fn new(src: &'s dyn RangeSource) -> Cursor<'s> {
        Cursor::over(Handle::Borrowed(src))
    }

    /// A cursor that keeps the source alive itself.
    pub(crate) fn shared(src: Arc<dyn RangeSource>) -> Cursor<'static> {
        Cursor::over(Handle::Shared(src))
    }

    fn over(src: Handle<'s>) -> Cursor<'s> {
        Cursor {
            src,
            buf: Vec::new(),
            base: 0,
            start: 0,
            end: 0,
            charged: 0,
            last_fill: 0,
            run: 0,
            ahead: MIN_READ,
            avail: 0,
            #[cfg(test)]
            moved: 0,
        }
    }

    /// Let a run of short forward refills grow the window to `read_ahead`
    /// bytes, capped at [`READ_AHEAD_CAP`]. The caller passes its
    /// `MemoryPolicy::read_ahead`, which API 5.2 makes the bound on how
    /// far past the byte in hand the engine may ask a source to read.
    pub(crate) fn with_read_ahead(mut self, read_ahead: u64) -> Self {
        self.ahead = usize::try_from(read_ahead)
            .unwrap_or(usize::MAX)
            .clamp(MIN_READ, READ_AHEAD_CAP);
        self
    }

    /// How many bytes from `from` the next refill may ask for, as a run of
    /// closely spaced refills earns (0: no growth). The growth never
    /// reaches past what the source already holds, so it does not by
    /// itself make a source still receiving bytes wait; once grown, a
    /// refill fills the window as every refill here always has, which
    /// stays inside the read-ahead bound.
    fn widen(&mut self, from: u64) -> usize {
        let step = from.wrapping_sub(self.last_fill);
        if from > self.last_fill && step <= CLOSE_STEP {
            self.run = self.run.saturating_add(1);
        } else {
            self.run = 0;
        }
        self.last_fill = from;
        if self.run < RUN_TO_GROW || self.ahead <= MIN_READ {
            return 0;
        }
        let end = from + self.ahead as u64;
        if self.avail < end {
            self.avail = self.avail.max(self.src.get().available());
        }
        usize::try_from(self.avail.min(end).saturating_sub(from)).unwrap_or(0)
    }

    /// Live bytes: what the window can serve without reading.
    #[inline]
    fn live(&self) -> usize {
        self.end - self.start
    }

    /// The source behind the cursor.
    pub(crate) fn source(&self) -> &dyn RangeSource {
        self.src.get()
    }

    fn grow_to(&mut self, want: usize) {
        if self.buf.len() >= want {
            return;
        }
        // Geometric, so N headers cost O(log N) allocations (API 2.4).
        let new_len = want.max(MIN_READ).max(self.buf.len().saturating_mul(2));
        self.buf.resize(new_len, 0);
        let now = self.buf.len() as u64;
        memory::charge(now - self.charged);
        self.charged = now;
    }

    /// Make `need` bytes from `at` available, and return exactly those bytes.
    /// A source that ends first is [`ErrorKind::Truncated`].
    pub(crate) fn peek(&mut self, at: u64, need: usize) -> Result<&[u8]> {
        let got = self.peek_upto(at, need)?.len();
        if got >= need {
            Ok(&self.buf[self.start..self.start + need])
        } else {
            Err(Error::new(ErrorKind::Truncated).with_offset(at + got as u64))
        }
    }

    /// Put the window's front at `at`, which is a forward step inside the
    /// window and a restart outside it. Nothing is copied either way.
    fn advance_to(&mut self, at: u64) {
        if at < self.base || at > self.base + self.live() as u64 {
            // A backward step or a jump past the buffer: restart the window.
            self.start = 0;
            self.end = 0;
            self.base = at;
            return;
        }
        self.start += (at - self.base) as usize;
        self.base = at;
        if self.start == self.end {
            // Nothing live: rewind to the front for the longest possible
            // next read, and there is nothing to slide to get there.
            self.start = 0;
            self.end = 0;
        }
    }

    /// Make the tail able to take a read that brings the window to `want`
    /// live bytes, sliding the live bytes forward only when it cannot.
    fn make_room(&mut self, want: usize) {
        if self.buf.len() - self.end >= want - self.live() {
            return;
        }
        // Sliding first is usually enough, and is what keeps a long
        // forward walk inside one buffer. It is the ONLY place this type
        // moves a byte, and it happens once per bufferful read rather than
        // once per step, so its cost is bounded by the bytes read.
        if self.start > 0 {
            let live = self.live();
            self.buf.copy_within(self.start..self.end, 0);
            #[cfg(test)]
            {
                self.moved += live as u64;
            }
            self.start = 0;
            self.end = live;
        }
        self.grow_to(want.max(MIN_READ));
    }

    /// Make up to `want` bytes from `at` available, and return what there is
    /// (possibly fewer, and possibly none at the end of the source).
    pub(crate) fn peek_upto(&mut self, at: u64, want: usize) -> Result<&[u8]> {
        self.advance_to(at);
        if self.live() < want {
            // A run of closely spaced refills is a walk over many small
            // members: one wider read replaces several narrow ones.
            let wide = self.widen(self.base + self.live() as u64);
            self.make_room(want.max(self.live() + wide));
            let room = self.buf.len();
            let from = self.base + self.live() as u64;
            let n = read_upto_at(self.src.get(), from, &mut self.buf[self.end..room])?;
            self.end += n;
        }
        let n = want.min(self.live());
        Ok(&self.buf[self.start..self.start + n])
    }

    /// Bytes slid by a compaction over this cursor's life.
    #[cfg(test)]
    pub(crate) fn bytes_moved(&self) -> u64 {
        self.moved
    }

    /// Bytes this cursor's buffer holds, for the operation's own peak.
    pub(crate) fn working_bytes(&self) -> u64 {
        self.charged
    }

    /// Take up to `buf.len()` bytes of member data at `at`, serving them
    /// from the window first so no byte range is read twice (API 2.5).
    /// Returns how many bytes landed; 0 means the source ended.
    pub(crate) fn take(&mut self, at: u64, buf: &mut [u8]) -> Result<usize> {
        if at >= self.base && at < self.base + self.live() as u64 {
            let from = self.start + (at - self.base) as usize;
            let n = (self.end - from).min(buf.len());
            buf[..n].copy_from_slice(&self.buf[from..from + n]);
            return Ok(n);
        }
        // Nothing buffered here: read straight through and drop the window,
        // so the next header read starts a fresh one.
        self.base = at;
        self.start = 0;
        self.end = 0;
        read_upto_at(self.src.get(), at, buf)
    }

    /// Whether the byte at `at` is already in the window, so a read of it
    /// through [`Self::take`] costs the source nothing.
    #[cfg(feature = "parallel")]
    pub(crate) fn holds(&self, at: u64) -> bool {
        at >= self.base && at < self.base + self.live() as u64
    }

    /// How many bytes from `at` on are in the window already: what a
    /// caller that reads the rest of a range on other threads takes through
    /// [`Self::take`] first, so no byte is read twice (`read::across`).
    #[cfg(feature = "parallel")]
    pub(crate) fn held_from(&self, at: u64) -> usize {
        if self.holds(at) {
            (self.base + self.live() as u64 - at) as usize
        } else {
            0
        }
    }

    /// The source itself, where this cursor keeps it alive, for a reader
    /// that takes a range of it on other threads (`read::wide`). `None`
    /// for a borrowed source, which cannot outlive the borrow.
    #[cfg(feature = "parallel")]
    pub(crate) fn shared_source(&self) -> Option<Arc<dyn RangeSource>> {
        match &self.src {
            Handle::Shared(src) => Some(Arc::clone(src)),
            Handle::Borrowed(_) => None,
        }
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        memory::release(self.charged);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A source that answers short reads and counts every call.
    struct Choppy {
        data: Vec<u8>,
        chunk: usize,
        reads: AtomicUsize,
    }

    impl RangeSource for Choppy {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let Ok(start) = usize::try_from(offset) else {
                return Ok(0);
            };
            let Some(rest) = self.data.get(start..) else {
                return Ok(0);
            };
            let n = rest.len().min(buf.len()).min(self.chunk);
            buf[..n].copy_from_slice(&rest[..n]);
            Ok(n)
        }
        fn available(&self) -> u64 {
            self.data.len() as u64
        }
        fn len(&self) -> Option<u64> {
            Some(self.data.len() as u64)
        }
    }

    fn choppy(len: usize, chunk: usize) -> Choppy {
        Choppy {
            data: (0..len).map(|i| i as u8).collect(),
            chunk,
            reads: AtomicUsize::new(0),
        }
    }

    #[test]
    fn short_reads_are_looped_over() {
        let src = choppy(20_000, 7);
        let mut cur = Cursor::new(&src);
        assert_eq!(cur.peek(0, 100).unwrap()[99], 99);
        assert_eq!(cur.peek(10_000, 5).unwrap()[0], 10_000u16 as u8);
    }

    #[test]
    fn a_forward_walk_does_not_read_once_per_field() {
        let src = choppy(64 * 1024, 64 * 1024);
        let mut cur = Cursor::new(&src);
        for at in 0..2000u64 {
            let _ = cur.peek(at, 8).unwrap();
        }
        // 2,007 bytes touched; a 4 KiB buffer covers them in one read.
        assert_eq!(src.reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_source_that_ends_early_is_truncated() {
        let src = choppy(10, 10);
        let mut cur = Cursor::new(&src);
        let err = cur.peek(4, 20).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Truncated));
        assert_eq!(err.offset(), Some(10));
    }

    #[test]
    fn take_serves_buffered_bytes_rather_than_reading_them_again() {
        let src = choppy(8192, 8192);
        let mut cur = Cursor::new(&src);
        let _ = cur.peek(0, 8).unwrap();
        let before = src.reads.load(Ordering::Relaxed);
        let mut buf = [0u8; 64];
        let n = cur.take(8, &mut buf).unwrap();
        assert!(n >= 64, "served from the window");
        assert_eq!(src.reads.load(Ordering::Relaxed), before, "no extra read");
        assert_eq!(buf[0], 8);
    }

    /// The shape `f/test-rar4-20000-vsnull` walks: twenty thousand headers
    /// read forward at a small stride over one source.
    ///
    /// A cursor that puts its live bytes back at `buf[0]` on every step
    /// slides about half a window per step, so it moves an order of
    /// magnitude MORE than it reads: measured at about 40.9 MB moved to
    /// read 4.27 MB, and 41.2% of the walk's self time. This asserts the
    /// other side of that, and it is the test that fails if the
    /// compaction is ever quietly restored, since every other test here
    /// passes either way.
    #[test]
    fn a_forward_walk_slides_far_less_than_it_reads() {
        let steps = 20_000u64;
        let stride = 192u64;
        let len = (steps * stride) as usize + MIN_READ;
        let src = choppy(len, usize::MAX);
        let mut cur = Cursor::new(&src);
        for i in 0..steps {
            let got = cur.peek_upto(i * stride, 32).unwrap();
            assert_eq!(got.len(), 32, "the window serves every step");
            assert_eq!(got[0], (i * stride) as u8, "and serves the right byte");
        }
        let moved = cur.bytes_moved();
        let read = steps * stride;
        assert!(
            moved * 10 <= read,
            "slid {moved} bytes to read {read}: the window is being \
             compacted per step rather than per read"
        );
    }

    /// Many small members read forward: the shape the adaptive window is
    /// for. Every byte served must be the source's, the calls must fall
    /// several fold against the same walk at the floor, and
    /// the charge must stay at the cap.
    #[test]
    fn a_run_of_close_refills_grows_the_window_to_the_allowance() {
        let steps = 20_000u64;
        let stride = 4_000u64;
        let len = (steps * stride) as usize + MIN_READ;
        let walk = |ahead: u64| {
            let src = choppy(len, usize::MAX);
            let mut cur = Cursor::new(&src).with_read_ahead(ahead);
            for i in 0..steps {
                let got = cur.peek_upto(i * stride, 64).unwrap();
                assert_eq!(got.len(), 64);
                assert_eq!(got[0], (i * stride) as u8);
                assert_eq!(got[63], (i * stride + 63) as u8);
            }
            (src.reads.load(Ordering::Relaxed), cur.working_bytes())
        };
        let (floor_reads, floor_bytes) = walk(MIN_READ as u64);
        let (reads, bytes) = walk(4 * 1024 * 1024);
        assert_eq!(floor_bytes, MIN_READ as u64, "the floor never grows");
        // Measured 1,181 against 10,000 on 25 Sep 2026: one 64 KiB read
        // stands in for sixteen at most, less the tail each slide keeps.
        assert!(
            reads * 5 <= floor_reads,
            "{reads} reads against {floor_reads}"
        );
        assert!(bytes <= READ_AHEAD_CAP as u64, "charged {bytes}");
    }

    /// Jumps farther than a close step never earn growth: one member's
    /// data area between headers is the case this guards.
    #[test]
    fn far_refills_never_grow_the_window() {
        let src = choppy(64 * 1024 * 1024, usize::MAX);
        let mut cur = Cursor::new(&src).with_read_ahead(4 * 1024 * 1024);
        for i in 0..100u64 {
            let _ = cur.peek(i * 100_000, 32).unwrap();
        }
        assert_eq!(cur.working_bytes(), MIN_READ as u64);
    }

    /// A source still receiving bytes: growth stops at what it holds.
    #[test]
    fn growth_stops_at_what_the_source_holds() {
        struct Arriving(Choppy, u64);
        impl RangeSource for Arriving {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.read_at(offset, buf)
            }
            fn available(&self) -> u64 {
                self.1
            }
            fn len(&self) -> Option<u64> {
                None
            }
        }
        let held = 5 * MIN_READ as u64;
        let src = Arriving(choppy(1 << 20, usize::MAX), held);
        let mut cur = Cursor::new(&src).with_read_ahead(4 * 1024 * 1024);
        let mut at = 0u64;
        while at + 64 < held {
            let got = cur.peek_upto(at, 64).unwrap();
            assert_eq!(got[0], at as u8);
            at += 1000;
        }
        assert!(
            cur.working_bytes() <= 2 * held,
            "charged {}",
            cur.working_bytes()
        );
        assert!(cur.working_bytes() < READ_AHEAD_CAP as u64);
    }

    #[test]
    fn peek_upto_returns_what_there_is() {
        let src = choppy(10, 10);
        let mut cur = Cursor::new(&src);
        assert_eq!(cur.peek_upto(6, 20).unwrap().len(), 4);
        assert!(cur.peek_upto(10, 20).unwrap().is_empty());
    }

    /// A source whose reads fail from `bad` on.
    #[cfg(feature = "parallel")]
    struct Failing {
        inner: Choppy,
        bad: u64,
    }

    #[cfg(feature = "parallel")]
    impl RangeSource for Failing {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            if offset + buf.len() as u64 > self.bad {
                if offset >= self.bad {
                    return Err(std::io::Error::other("bad sector"));
                }
                let head = (self.bad - offset) as usize;
                return self.inner.read_at(offset, &mut buf[..head]);
            }
            self.inner.read_at(offset, buf)
        }
        fn available(&self) -> u64 {
            self.inner.available()
        }
        fn len(&self) -> Option<u64> {
            self.inner.len()
        }
    }

    /// The deep read answers exactly what the single read answers: the
    /// same bytes, the same count where the source ends inside the
    /// range, whatever the parts, the length and how short the source's
    /// own answers are.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_deep_read_lands_what_a_single_read_lands() {
        let len = (5 << 20) + 12_345;
        for chunk in [1, 4095, 64 * 1024, usize::MAX] {
            // A one-byte dribble over 5 MiB is five million calls a part;
            // a shorter source keeps it quick and still ends mid-range.
            let len = if chunk == 1 { deep::FLOOR + 777 } else { len };
            let src = choppy(len, chunk);
            for (at, want) in [
                (0u64, deep::FLOOR),
                (3, deep::FLOOR + 1),
                (4096, len - 4096),
                (17, len),
                (0, len + 999_999),
            ] {
                for parts in [1, 2, 3, 4, 8, 64] {
                    let mut single = vec![0xAAu8; want];
                    let one = read_serial(&src, at, &mut single).unwrap();
                    let mut split = vec![0x55u8; want];
                    let got = deep::deeply(parts, || read_upto_at(&src, at, &mut split)).unwrap();
                    assert_eq!(got, one, "chunk {chunk} at {at} want {want} parts {parts}");
                    assert_eq!(
                        split[..got],
                        single[..one],
                        "chunk {chunk} at {at} parts {parts}"
                    );
                }
            }
        }
    }

    /// A read below the floor, or outside `deeply`, is one read on the
    /// calling thread: the calls it makes are the single read's.
    #[cfg(feature = "parallel")]
    #[test]
    fn only_a_big_read_inside_deeply_is_split() {
        let src = choppy(8 << 20, usize::MAX);
        let mut buf = vec![0u8; deep::FLOOR - 1];
        deep::deeply(4, || read_upto_at(&src, 0, &mut buf)).unwrap();
        assert_eq!(src.reads.load(Ordering::Relaxed), 1);
        let mut buf = vec![0u8; 4 << 20];
        read_upto_at(&src, 0, &mut buf).unwrap();
        assert_eq!(src.reads.load(Ordering::Relaxed), 2);
        deep::deeply(4, || read_upto_at(&src, 0, &mut buf)).unwrap();
        assert_eq!(src.reads.load(Ordering::Relaxed), 6);
        // The setting is the scope's alone, a panic inside it included.
        let caught = std::panic::catch_unwind(|| deep::deeply(4, || panic!("inside")));
        assert!(caught.is_err());
        read_upto_at(&src, 0, &mut buf).unwrap();
        assert_eq!(src.reads.load(Ordering::Relaxed), 7);
    }

    /// A source error inside the range is the single read's error, at the
    /// single read's offset, whichever part meets it.
    #[cfg(feature = "parallel")]
    #[test]
    fn a_deep_read_fails_where_the_single_read_fails() {
        for bad in [0u64, 4096, 1 << 20, (3 << 20) + 5] {
            let src = Failing {
                inner: choppy(8 << 20, 64 * 1024),
                bad,
            };
            let mut single = vec![0u8; 4 << 20];
            let one = read_serial(&src, 0, &mut single).unwrap_err();
            for parts in [2, 4, 8] {
                let mut split = vec![0u8; 4 << 20];
                let err = deep::deeply(parts, || read_upto_at(&src, 0, &mut split)).unwrap_err();
                assert!(matches!(err.kind(), ErrorKind::Source(_)), "bad {bad}");
                assert_eq!(err.offset(), one.offset(), "bad {bad} parts {parts}");
            }
        }
    }

    /// The parts never pass the width, so `-mt1` reads on one thread.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_parts_never_pass_the_width() {
        assert_eq!(deep::parts(1), 1);
        assert_eq!(deep::parts(0), 1);
        assert!(deep::parts(2) <= 2);
        assert!(deep::parts(64) <= 64);
    }
}
