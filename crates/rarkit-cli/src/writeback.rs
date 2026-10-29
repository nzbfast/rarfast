//! WRITEBACK BEHIND THE CURSOR, the middle form of the big-member write on
//! Linux.
//!
//! The row is judged by the wall with the DATA ON DISK, with a floor on the
//! process wall. A cached write returns when the copy into the
//! page cache is done and leaves gigabytes dirty for the flusher, which on
//! ext4 writes them back slower than a direct stream (a Zen 4 rental: 1.70
//! against 2.27 GB/s; `io_ceiling`); a direct write (`unbuffered`) puts the
//! data on disk soonest but holds the process to the disk's pace. This form
//! keeps the cached write and, every [`STEP`] bytes, asks the kernel to START
//! writing the step behind the cursor (`sync_file_range` with
//! `SYNC_FILE_RANGE_WRITE`: no wait, in order, at once), and to DROP the step
//! [`BEHIND`] bytes back (`posix_fadvise(POSIX_FADV_DONTNEED)`, which lets go
//! of pages already written back and leaves dirty ones alone), so a 50 GiB
//! member does not evict everything else from memory as it lands. Both calls
//! are advisory: a refusal changes nothing but the pacing.
//!
//! Two `libc` calls under the per-function allow,
//! Linux with glibc only, where the crate already links `libc`.
//!
//! PACED UNDER A CGROUP MEMORY CAP ([`Pace`]). A
//! cgroup's limit counts the page cache its processes dirty, and where the
//! decoders outrun the drive the kernel can find the whole of what the
//! process leaves of the cap dirty and not yet under writeback, nothing clean
//! to take back, and kill the process: `x` at the default width under
//! `MemoryMax` 512M and 1G, exit 137 inside two seconds with a partial file
//! left (counted 3 Oct 2026, kernel 7.0, ext4). There is
//! no buffer of ours in it to shrink, so under a cap every cached member's
//! writes are PACED: writeback is started behind the cursor as above and the
//! writer WAITS for its oldest step once the output this process has written
//! and not yet seen on the drive passes a window sized from the cap. With no
//! cap nothing here runs.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};

/// The step: writeback is started for each of these as the cursor leaves it.
const STEP: u64 = 8 << 20;

/// How far behind the cursor a step is asked to be dropped: long enough for
/// its writeback to have finished on any disk the step rate allows.
const BEHIND: u64 = 64 << 20;

/// A member's writeback cursor.
pub(crate) struct Behind {
    /// Bytes for which writeback has been started.
    marked: u64,
    /// The pacing of a member written under a cgroup memory cap; `None`
    /// with no cap, which is every line of this type before pacing was added.
    paced: Option<Paced>,
}

impl Behind {
    /// The cursor of a member written through the cache from its first
    /// byte: write-behind where `behind` says the form is that one, PACED
    /// where the process runs under a cgroup memory cap whatever the form,
    /// and none otherwise.
    pub(crate) fn at_open(behind: bool) -> Option<Behind> {
        Behind::under(pace(), 0, behind)
    }

    /// The cursor of a member whose first `written` bytes went past the
    /// cache (`unbuffered`) before it fell back to the cache: as
    /// [`Behind::at_open`], writeback started from the step they end in.
    pub(crate) fn after_direct(written: u64, behind: bool) -> Option<Behind> {
        Behind::under(pace(), written, behind)
    }

    fn under(pace: Option<&'static Pace>, written: u64, behind: bool) -> Option<Behind> {
        match pace {
            Some(pace) => Some(Behind {
                marked: written,
                paced: Some(Paced {
                    pace,
                    counted: written,
                    waited: written,
                }),
            }),
            None if behind => Some(Behind {
                marked: written / STEP * STEP,
                paced: None,
            }),
            None => None,
        }
    }

    /// `written` bytes are now in the cache: start writeback for every
    /// whole step behind the cursor not yet started, and drop the steps
    /// [`BEHIND`] further back.
    pub(crate) fn advance(&mut self, file: &File, written: u64) {
        if let Some(paced) = self.paced.as_mut() {
            return paced.advance(file, &mut self.marked, written);
        }
        while self.marked + STEP <= written {
            advise(file, self.marked, STEP);
            self.marked += STEP;
        }
    }

    /// The member is complete: start writeback for its tail as well.
    pub(crate) fn finish(&mut self, file: &File, written: u64) {
        if let Some(paced) = self.paced.as_mut() {
            return paced.finish(file, &mut self.marked, written);
        }
        if written > self.marked {
            advise(file, self.marked, written - self.marked);
            self.marked = written;
        }
    }
}

/// The step a paced member's writeback is started and waited for in.
const PACE_STEP: u64 = 4 << 20;

/// The share of a cgroup memory cap that this process's output may hold
/// written and not yet seen on the drive: an eighth. The policy admits a
/// window of half the cap, and the decoder's own memory beside it was 59 to
/// 62 MiB, so an eighth more leaves a quarter of the cap and upward for the
/// kernel, the writers' overshoot and clean cache.
const PACE_SHARE: u64 = 8;

/// The least window: two steps, so a writer always has one to wait for.
const PACE_LEAST: u64 = 2 * PACE_STEP;

/// What every paced member of this process shares: the window, and the
/// output written through the cache that no wait has yet covered.
pub(crate) struct Pace {
    /// The bytes [`Pace::pool`] may reach before a writer waits.
    window: u64,
    /// Bytes written through the cache and not yet waited for, by open
    /// members and closed ones alike.
    pool: AtomicU64,
    /// The part of the pool that belongs to members already closed, which
    /// only [`Pace::flush`] can wait for.
    closed: AtomicU64,
    /// One flush at a time: the writers behind it are held, which is the
    /// pacing.
    flush: std::sync::Mutex<()>,
}

impl Pace {
    const fn new(window: u64) -> Pace {
        Pace {
            window,
            pool: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            flush: std::sync::Mutex::new(()),
        }
    }

    fn over(&self) -> bool {
        self.pool.load(Ordering::Relaxed) > self.window
    }

    fn waited(&self, bytes: u64) {
        let _ = self
            .pool
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pool| {
                Some(pool.saturating_sub(bytes))
            });
    }

    /// The closed members' output waited for, all of it at once, through
    /// the file system `file` is on (`syncfs`; refused, the file's own
    /// `fdatasync`).
    fn flush(&self, file: &File) {
        let _held = self.flush.lock().unwrap_or_else(|p| p.into_inner());
        if !self.over() {
            return;
        }
        let closed = self.closed.swap(0, Ordering::Relaxed);
        if closed == 0 {
            return;
        }
        sync_all_of(file);
        self.waited(closed);
    }
}

/// The window under a cgroup memory cap of `cap` bytes.
const fn window_under(cap: u64) -> u64 {
    let window = cap / PACE_SHARE;
    if window < PACE_LEAST {
        PACE_LEAST
    } else {
        window
    }
}

/// This process's pace: `Some` under a cgroup memory cap (the smallest on
/// the process's own cgroup path, as the memory policy reads it, read once
/// there and not again here), `None` with no cap. A `reserve-knob` build
/// takes `RARFAST_PACE`: `off`, or a window in MiB.
fn pace() -> Option<&'static Pace> {
    static PACE: std::sync::OnceLock<Option<Pace>> = std::sync::OnceLock::new();
    PACE.get_or_init(|| {
        let window = rarkit::memory::container_cap().map(window_under);
        #[cfg(feature = "reserve-knob")]
        let window = match std::env::var("RARFAST_PACE").as_deref().map(str::trim) {
            Ok("off") => None,
            Ok(mib) => mib.parse::<u64>().ok().map(|mib| mib << 20).or(window),
            Err(_) => window,
        };
        #[cfg(feature = "reserve-knob")]
        eprintln!("rarfast pace window: {window:?}");
        window.map(Pace::new)
    })
    .as_ref()
}

/// One member's place in the pace.
struct Paced {
    pace: &'static Pace,
    /// Bytes of this member counted into the pool.
    counted: u64,
    /// Bytes of this member waited for (or written past the cache).
    waited: u64,
}

impl Paced {
    /// `written` bytes are now in the cache: count them, start writeback
    /// for every whole step not yet started, and while the pool is over
    /// the window wait for this member's oldest step; then, if it still
    /// is, for the closed members' output.
    fn advance(&mut self, file: &File, marked: &mut u64, written: u64) {
        self.pace
            .pool
            .fetch_add(written - self.counted, Ordering::Relaxed);
        self.counted = written;
        while *marked + PACE_STEP <= written {
            start(file, *marked, PACE_STEP);
            *marked += PACE_STEP;
        }
        if !self.pace.over() {
            return;
        }
        while self.pace.over() && self.waited < written {
            let to = if self.waited + PACE_STEP <= *marked {
                self.waited + PACE_STEP
            } else {
                written
            };
            wait(file, self.waited, to - self.waited);
            self.pace.waited(to - self.waited);
            self.waited = to;
            *marked = (*marked).max(to);
        }
        if self.pace.over() {
            self.pace.flush(file);
        }
    }

    /// The member is complete: its tail counted, and what was not waited
    /// for either waited for now, where the pool is over the window, or
    /// left to the pool as a closed member's.
    fn finish(&mut self, file: &File, marked: &mut u64, written: u64) {
        self.pace
            .pool
            .fetch_add(written.saturating_sub(self.counted), Ordering::Relaxed);
        self.counted = written;
        let left = written.saturating_sub(self.waited);
        if left == 0 {
            return;
        }
        self.pace.closed.fetch_add(left, Ordering::Relaxed);
        self.waited = written;
        if self.pace.over() {
            self.pace.flush(file);
        } else if written >= *marked + PACE_STEP {
            start(file, *marked, written - *marked);
        }
        *marked = written;
    }
}

/// `sync_file_range(SYNC_FILE_RANGE_WRITE)` over `[from, from + len)`: start
/// writeback, no wait. A refusal is ignored: advice.
#[allow(unsafe_code)]
fn start(file: &File, from: u64, len: u64) {
    // SAFETY: a plain system call on a descriptor this process holds open for
    // the length of the call (the `&File` borrow); it reads and writes no
    // memory of ours.
    unsafe {
        libc::sync_file_range(
            file.as_raw_fd(),
            from as i64,
            len as i64,
            libc::SYNC_FILE_RANGE_WRITE,
        );
    }
}

/// `sync_file_range` over `[from, from + len)` with the wait before, the
/// write and the wait after: the range is on the drive, or on its way past
/// the cache's dirty count, when it returns. Where the file system refuses
/// the call the whole file is waited for (`fdatasync`), and a refusal of
/// that is ignored: the pacing is lost there, not the bytes.
#[allow(unsafe_code)]
fn wait(file: &File, from: u64, len: u64) {
    let fd = file.as_raw_fd();
    // SAFETY: plain system calls on a descriptor this process holds open for
    // the length of the calls (the `&File` borrow); neither reads or writes
    // any memory of ours.
    unsafe {
        let flags = libc::SYNC_FILE_RANGE_WAIT_BEFORE
            | libc::SYNC_FILE_RANGE_WRITE
            | libc::SYNC_FILE_RANGE_WAIT_AFTER;
        if libc::sync_file_range(fd, from as i64, len as i64, flags) != 0 {
            libc::fdatasync(fd);
        }
    }
}

/// `syncfs` on the file system `file` is on, and where that is refused the
/// file's own `fdatasync`.
#[allow(unsafe_code)]
fn sync_all_of(file: &File) {
    let fd = file.as_raw_fd();
    // SAFETY: plain system calls on a descriptor this process holds open for
    // the length of the calls (the `&File` borrow); neither reads or writes
    // any memory of ours.
    unsafe {
        if libc::syncfs(fd) != 0 {
            libc::fdatasync(fd);
        }
    }
}

/// `sync_file_range(SYNC_FILE_RANGE_WRITE)` over `[from, from + len)` and
/// `posix_fadvise(POSIX_FADV_DONTNEED)` over the same length [`BEHIND`]
/// bytes back, both without waiting. Refusals are ignored: advice.
#[allow(unsafe_code)]
fn advise(file: &File, from: u64, len: u64) {
    let fd = file.as_raw_fd();
    // SAFETY: both are plain system calls on a descriptor this process holds
    // open for the length of the call (the `&File` borrow); neither reads or
    // writes any memory of ours, and each is advisory.
    unsafe {
        libc::sync_file_range(fd, from as i64, len as i64, libc::SYNC_FILE_RANGE_WRITE);
        if from >= BEHIND {
            libc::posix_fadvise(
                fd,
                (from - BEHIND) as i64,
                len as i64,
                libc::POSIX_FADV_DONTNEED,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const MIB: u64 = 1 << 20;

    /// A file in the build's own scratch, removed when the guard goes.
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("rarfast-pace-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn pace_of(window: u64) -> &'static Pace {
        Box::leak(Box::new(Pace::new(window)))
    }

    /// An eighth of the cap, and never under two steps.
    #[test]
    fn the_window_is_an_eighth_of_the_cap() {
        assert_eq!(window_under(512 * MIB), 64 * MIB);
        assert_eq!(window_under(1024 * MIB), 128 * MIB);
        assert_eq!(window_under(256 * MIB), 32 * MIB);
        assert_eq!(window_under(16 * MIB), PACE_LEAST);
        assert_eq!(window_under(0), PACE_LEAST);
    }

    /// With no cap a cached member has no cursor, and a write-behind one
    /// has the cursor it had before pacing was added.
    #[test]
    fn with_no_cap_only_write_behind_has_a_cursor() {
        assert!(Behind::under(None, 0, false).is_none());
        assert!(Behind::under(None, 20 * MIB, false).is_none());
        let behind = Behind::under(None, 20 * MIB, true).unwrap();
        assert_eq!(behind.marked, 16 * MIB);
        assert!(behind.paced.is_none());
    }

    /// One big member under a pace: the pool never passes the window by
    /// more than the piece just written, the bytes are the bytes, and at
    /// its close what was not waited for is the closed members'.
    #[test]
    fn a_big_member_holds_the_pool_at_the_window() {
        let dir = scratch("big");
        let path = dir.0.join("big.bin");
        let pace = pace_of(8 * MIB);
        let mut file = File::create(&path).unwrap();
        let mut behind = Behind::under(Some(pace), 0, false).unwrap();
        let piece: Vec<u8> = (0..MIB as u32).map(|i| (i >> 3) as u8).collect();
        let mut written = 0;
        for _ in 0..48 {
            file.write_all(&piece).unwrap();
            written += MIB;
            behind.advance(&file, written);
            let pool = pace.pool.load(Ordering::Relaxed);
            assert!(pool <= 8 * MIB, "pool {pool} at {written}");
        }
        behind.finish(&file, written);
        let (pool, closed) = (
            pace.pool.load(Ordering::Relaxed),
            pace.closed.load(Ordering::Relaxed),
        );
        assert_eq!(pool, closed, "an open member's bytes left in the pool");
        assert!(pool <= 8 * MIB, "pool {pool} at the close");
        drop(file);
        let back = std::fs::read(&path).unwrap();
        assert_eq!(back.len() as u64, written);
        assert!(back.chunks(MIB as usize).all(|chunk| chunk == piece));
    }

    /// Many members under a step each: nothing is waited for a member at
    /// a time, and the closed members' output is flushed together when the
    /// pool passes the window, so it never passes it by more than one.
    #[test]
    fn small_members_are_flushed_together() {
        let dir = scratch("small");
        let pace = pace_of(8 * MIB);
        let piece = vec![0x5au8; 64 << 10];
        let mut most = 0;
        for at in 0..400 {
            let mut file = File::create(dir.0.join(format!("f{at}"))).unwrap();
            let mut behind = Behind::under(Some(pace), 0, false).unwrap();
            file.write_all(&piece).unwrap();
            behind.advance(&file, piece.len() as u64);
            behind.finish(&file, piece.len() as u64);
            most = most.max(pace.pool.load(Ordering::Relaxed));
            assert_eq!(
                pace.pool.load(Ordering::Relaxed),
                pace.closed.load(Ordering::Relaxed)
            );
        }
        assert!(most > 4 * MIB, "the pool never filled: {most}");
        assert!(most <= 8 * MIB + piece.len() as u64, "pool reached {most}");
        for at in [0, 399] {
            assert_eq!(std::fs::read(dir.0.join(format!("f{at}"))).unwrap(), piece);
        }
    }

    /// A member that left direct writing at `written` counts only what it
    /// writes through the cache after.
    #[test]
    fn a_member_that_left_direct_writing_counts_from_there() {
        let dir = scratch("left");
        let pace = pace_of(8 * MIB);
        let mut file = File::create(dir.0.join("m.bin")).unwrap();
        let piece = vec![7u8; MIB as usize];
        for _ in 0..5 {
            file.write_all(&piece).unwrap();
        }
        let mut behind = Behind::under(Some(pace), 4 * MIB, true).unwrap();
        behind.advance(&file, 5 * MIB);
        assert_eq!(pace.pool.load(Ordering::Relaxed), MIB);
        behind.finish(&file, 5 * MIB);
        assert_eq!(pace.closed.load(Ordering::Relaxed), MIB);
    }
}
