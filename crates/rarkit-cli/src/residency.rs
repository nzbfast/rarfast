//! Whether an archive file is already in the operating system's page cache
//! (WARM) or has to come off its device (COLD), from a small sample.
//!
//! **Why the command line asks.** The shape of read that is fastest off a
//! device is not the shape that is fastest out of memory. On an array of
//! hard disks a stored set of many members' cold `t` wants one reader in
//! order (6.04 s against 9.78 s at the width), and a file once cached wants
//! the whole width (a big member's `t` 0.60 s at twelve against 2.87 s at one; the NAS
//! rows, 1 Oct 2026). A download client tests what it has just written as
//! often as not, so a rule keyed on the device alone would give back the
//! warm row to win the cold one. This says which of the two a command is
//! looking at, once, before it reads.
//!
//! **The sample.** [`WINDOWS`] windows of [`WINDOW_PAGES`] pages each,
//! spread evenly from the file's first byte to its last: sixty-four pages
//! in all, asked of the kernel with `mincore` over one read-only mapping of
//! the file. Nothing is read and no page is touched: a mapping that is
//! never dereferenced faults nothing in, and `mincore` only reports. The
//! cost is the open, one `mmap`, sixteen `mincore` calls and one `munmap`,
//! about twenty system calls a command.
//!
//! **The verdict** is [`Residency::Resident`] when at least half the
//! sampled pages are in memory ([`SWITCH`]), [`Residency::Cold`] when fewer
//! are, and [`Residency::Unknown`] when the sample could not be taken. A
//! caller treats Unknown as it treats Resident: today's behaviour. That is
//! also what a kernel's caution amounts to: Linux since 5.2 answers "every
//! page resident" to a caller who neither owns the file nor may write it,
//! so such a file reads as warm and nothing changes for it.
//!
//! A partly cached file (a download still being flushed, a set whose first
//! volumes were just read) takes whichever side holds the majority of the
//! sample; the cost of the wrong side is bounded by the minority.
//!
//! Unix only; every other system answers Unknown.

// Off Unix there is no kernel to ask, so the sample's plan and its verdict
// have no caller there outside this module's tests.
#![cfg_attr(not(unix), allow(dead_code))]

use std::path::Path;

/// What the sample of a file says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Residency {
    /// At least [`SWITCH`] of the sampled pages are in the page cache.
    Resident,
    /// Fewer are: the file's bytes come off its device.
    Cold,
    /// The sample could not be taken.
    Unknown,
}

/// Windows in the sample, spread evenly over the file.
pub(crate) const WINDOWS: u64 = 16;

/// Pages in each window.
pub(crate) const WINDOW_PAGES: u64 = 4;

/// The sampled fraction at and above which a file counts as resident.
pub(crate) const SWITCH: f64 = 0.5;

/// Where the answer to "how many of these pages are in memory" comes from:
/// the kernel, or a test's own table.
pub(crate) trait Pages {
    /// The file's length in bytes and the page size.
    fn shape(&self) -> (u64, u64);
    /// How many of the `pages` pages starting at byte `offset` (a multiple
    /// of the page size, inside the file) are resident; `None` where the
    /// source cannot say.
    fn resident(&self, offset: u64, pages: u64) -> Option<u64>;
}

/// The windows of the sample for a file of `len` bytes: `(offset, pages)`,
/// each offset a multiple of `page`, each window inside the file, none
/// overlapping another. A file shorter than the whole sample is covered
/// page by page.
pub(crate) fn windows(len: u64, page: u64) -> Vec<(u64, u64)> {
    let total = len.div_ceil(page.max(1));
    if total == 0 || page == 0 {
        return Vec::new();
    }
    if total <= WINDOWS * WINDOW_PAGES {
        return vec![(0, total)];
    }
    // The first window at the first page, the last ending at the last one.
    let span = total - WINDOW_PAGES;
    (0..WINDOWS)
        .map(|i| (span * i / (WINDOWS - 1) * page, WINDOW_PAGES))
        .collect()
}

/// The fraction of the sample that is resident, and the verdict.
pub(crate) fn judge(source: &dyn Pages) -> (Option<f64>, Residency) {
    let (len, page) = source.shape();
    let plan = windows(len, page);
    if plan.is_empty() {
        return (None, Residency::Unknown);
    }
    let (mut resident, mut sampled) = (0u64, 0u64);
    for (offset, pages) in plan {
        let Some(got) = source.resident(offset, pages) else {
            return (None, Residency::Unknown);
        };
        resident += got.min(pages);
        sampled += pages;
    }
    let fraction = resident as f64 / sampled as f64;
    let verdict = if fraction >= SWITCH {
        Residency::Resident
    } else {
        Residency::Cold
    };
    (Some(fraction), verdict)
}

/// The sampled fraction of `path` in the page cache and the verdict.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_RESIDENT=1` or `=0` states the verdict and samples nothing.
pub(crate) fn of(path: &Path) -> (Option<f64>, Residency) {
    #[cfg(feature = "read-depth-knob")]
    match std::env::var("RARFAST_RESIDENT").as_deref().map(str::trim) {
        Ok("1") => return (None, Residency::Resident),
        Ok("0") => return (None, Residency::Cold),
        _ => {}
    }
    from_kernel(path)
}

#[cfg(unix)]
fn from_kernel(path: &Path) -> (Option<f64>, Residency) {
    match kernel::Mapped::open(path) {
        Some(mapped) => judge(&mapped),
        None => (None, Residency::Unknown),
    }
}

#[cfg(not(unix))]
fn from_kernel(_path: &Path) -> (Option<f64>, Residency) {
    (None, Residency::Unknown)
}

/// The kernel as the source: one read-only mapping of the file, asked
/// about with `mincore`, unmapped when dropped.
#[cfg(unix)]
mod kernel {
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use super::Pages;

    pub(super) struct Mapped {
        base: *mut libc::c_void,
        len: u64,
        page: u64,
    }

    impl Mapped {
        #[allow(unsafe_code)]
        pub(super) fn open(path: &Path) -> Option<Mapped> {
            let file = std::fs::File::open(path).ok()?;
            let meta = file.metadata().ok()?;
            if !meta.is_file() || meta.len() == 0 {
                return None;
            }
            let len = meta.len();
            let size = usize::try_from(len).ok()?;
            // SAFETY: `sysconf` takes no pointer.
            let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
            if page == 0 {
                return None;
            }
            // SAFETY: a fresh read-only shared mapping of a file this
            // function holds open, at an address the kernel chooses; no
            // memory of ours is replaced. The mapping outlives the
            // descriptor, which is how `mmap` is specified. It is never
            // dereferenced: only `mincore` and `munmap` are given its
            // address, so a file truncated meanwhile cannot fault here.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return None;
            }
            Some(Mapped { base, len, page })
        }
    }

    impl Pages for Mapped {
        fn shape(&self) -> (u64, u64) {
            (self.len, self.page)
        }

        #[allow(unsafe_code)]
        fn resident(&self, offset: u64, pages: u64) -> Option<u64> {
            let bytes = (pages * self.page).min(self.len.checked_sub(offset)?);
            let mut vec = vec![0u8; usize::try_from(pages).ok()?];
            // SAFETY: `offset` is a multiple of the page size inside the
            // mapping (`windows` builds it so, and it is checked against
            // the length above), `bytes` stays inside the mapping, and
            // `vec` holds one byte a page of that range, which is what
            // `mincore` writes. The cast is the vector's element type,
            // which is `c_uchar` on Linux and `c_char` on macOS.
            let rc = unsafe {
                libc::mincore(
                    self.base.add(usize::try_from(offset).ok()?),
                    usize::try_from(bytes).ok()?,
                    vec.as_mut_ptr().cast(),
                )
            };
            if rc != 0 {
                return None;
            }
            Some(vec.iter().filter(|b| **b & 1 == 1).count() as u64)
        }
    }

    impl Drop for Mapped {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: the mapping this value made, of the length it made
            // it with, unmapped once.
            let _ = unsafe { libc::munmap(self.base, self.len as usize) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file whose resident pages a test states: page `p` is in memory
    /// when `resident(p)` says so.
    struct Fake<F: Fn(u64) -> bool> {
        len: u64,
        page: u64,
        resident: F,
        fails: bool,
    }

    impl<F: Fn(u64) -> bool> Pages for Fake<F> {
        fn shape(&self) -> (u64, u64) {
            (self.len, self.page)
        }
        fn resident(&self, offset: u64, pages: u64) -> Option<u64> {
            assert_eq!(offset % self.page, 0, "a window starts on a page");
            assert!(
                offset + (pages - 1) * self.page < self.len,
                "a window is inside the file"
            );
            if self.fails {
                return None;
            }
            let first = offset / self.page;
            Some(
                (first..first + pages)
                    .filter(|p| (self.resident)(*p))
                    .count() as u64,
            )
        }
    }

    fn fake<F: Fn(u64) -> bool>(len: u64, resident: F) -> Fake<F> {
        Fake {
            len,
            page: 4096,
            resident,
            fails: false,
        }
    }

    const GIB: u64 = 1 << 30;

    #[test]
    fn the_sample_is_sixty_four_pages_from_the_first_to_the_last() {
        for page in [4096u64, 16384] {
            for len in [GIB, 12_881_000_237, 3 * GIB + 1, 300 * page] {
                let plan = windows(len, page);
                assert_eq!(plan.len() as u64, WINDOWS);
                assert_eq!(
                    plan.iter().map(|w| w.1).sum::<u64>(),
                    WINDOWS * WINDOW_PAGES
                );
                assert_eq!(plan[0].0, 0, "the first window is the file's first pages");
                let total = len.div_ceil(page);
                let (last, pages) = plan[plan.len() - 1];
                assert_eq!(
                    last / page + pages,
                    total,
                    "the last window ends at the last page"
                );
                for pair in plan.windows(2) {
                    assert_eq!(pair[0].0 % page, 0);
                    assert!(
                        pair[0].0 + pair[0].1 * page <= pair[1].0,
                        "no window overlaps the next"
                    );
                }
            }
        }
    }

    #[test]
    fn a_short_file_is_sampled_page_by_page() {
        assert_eq!(windows(0, 4096), Vec::new());
        assert_eq!(windows(1, 4096), vec![(0, 1)]);
        assert_eq!(windows(64 * 4096, 4096), vec![(0, 64)]);
        assert_eq!(windows(64 * 4096 + 1, 4096).len() as u64, WINDOWS);
    }

    #[test]
    fn a_cached_file_is_resident_and_an_uncached_one_cold() {
        assert_eq!(
            judge(&fake(12 * GIB, |_| true)),
            (Some(1.0), Residency::Resident)
        );
        assert_eq!(
            judge(&fake(12 * GIB, |_| false)),
            (Some(0.0), Residency::Cold)
        );
        // Only the headers at the front are in memory, as after a listing.
        let (fraction, verdict) = judge(&fake(12 * GIB, |p| p < 16));
        assert_eq!(verdict, Residency::Cold);
        assert_eq!(fraction, Some(4.0 / 64.0));
    }

    #[test]
    fn a_partly_cached_file_goes_with_the_majority_of_the_sample() {
        let pages = 12 * GIB / 4096;
        // The first third cached: cold. The first two thirds: resident.
        let third = judge(&fake(12 * GIB, |p| p < pages / 3));
        assert_eq!(third.1, Residency::Cold);
        assert!(
            third.0.is_some_and(|f| (0.25..0.45).contains(&f)),
            "{third:?}"
        );
        let two = judge(&fake(12 * GIB, |p| p < 2 * pages / 3));
        assert_eq!(two.1, Residency::Resident);
        // Exactly half the sample is the switch, and counts as resident.
        let half = judge(&fake(12 * GIB, |p| p < pages / 2));
        assert_eq!(half, (Some(0.5), Residency::Resident));
        // Every other page, as a file read sparsely: half, resident.
        assert_eq!(
            judge(&fake(12 * GIB, |p| p % 2 == 0)).1,
            Residency::Resident
        );
    }

    #[test]
    fn a_source_that_cannot_say_is_unknown() {
        let mut source = fake(12 * GIB, |_| true);
        source.fails = true;
        assert_eq!(judge(&source), (None, Residency::Unknown));
        assert_eq!(judge(&fake(0, |_| true)), (None, Residency::Unknown));
    }

    /// The kernel's own answer for a file this test has just written: the
    /// pages are in the cache, so the sample says resident. (The cold side
    /// needs a file system that drops pages on request, which a temporary
    /// directory in memory does not; the timed runs prove it.)
    #[cfg(unix)]
    #[test]
    fn a_file_just_written_reads_as_resident() {
        let path = std::env::temp_dir().join(format!("rarfast-residency-{}", std::process::id()));
        std::fs::write(&path, vec![7u8; 3 << 20]).unwrap();
        let (fraction, verdict) = of(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(verdict, Residency::Resident, "{fraction:?}");
        assert!(of(Path::new("/nonexistent/rarfast-residency")).1 == Residency::Unknown);
    }
}
