//! The bound on volumes opened AHEAD of the workers that read them.
//!
//! **What it is for.** The pool takes a member split across volumes over
//! its fragment list (`extract::Split`): the walk crosses to each next
//! volume, checks the continuation header, and sends the worker that
//! fragment with its volume's source, which is an open file. The walk only
//! reads headers, so it reaches the end of a member long before the
//! member's worker has read its bytes, and every volume it crossed stays
//! open behind it. With nothing to hold it back the walk opened a whole
//! set: `rarfast x` of eight stored members in 581 volumes of 15 MB ended
//! `Too many open files` on macOS, whose default limit is 256 descriptors,
//! with three members written, and a small-scale set of 2,403 volumes did
//! the same under a limit of 1,024, which is Linux's
//! (measured 1 Oct 2026). The walk reading the same sets
//! itself holds one volume open at a time and never failed.
//!
//! **The bound.** A fragment is forwarded only while fewer than [`limit`]
//! forwarded fragments are still unread: the walk takes a [`Held`] before
//! it crosses to the next volume ([`take`]), the fragment carries it to the
//! worker, and the worker drops it when it has read that fragment to its
//! end. At the limit the walk WAITS. It waits for workers only: every
//! holder is a fragment already sent to a worker the pool has started,
//! which reads it without the walk, so the wait always ends.
//!
//! **Per process, because the limit is.** One count for every extraction
//! in the process, read against the soft `RLIMIT_NOFILE` each time, so a
//! caller that raises its own limit is given the room at once. The limit
//! is never raised here.
//!
//! **What it costs.** Nothing where the walk was not that far ahead: a
//! lock and an unlock per volume crossed. Where it binds, the walk reaches
//! the NEXT member only once this one's worker is within the bound of its
//! end, so fewer members are read at once than the pool's breadth: a set
//! that failed now extracts, at the width its descriptors allow.

use std::sync::{Condvar, Mutex};

/// Forwarded fragments not yet read to their end, in this process.
static HELD: Mutex<usize> = Mutex::new(0);
static FREED: Condvar = Condvar::new();

/// The most fragments forwarded ahead where the limit is unknown, has no
/// finite value, or is very large: no drive is read faster by more open
/// volumes than this, and each is a file the caller keeps open.
const MOST: usize = 4096;

/// One forwarded fragment's place in the count, given back when dropped.
pub(crate) struct Held(());

impl Drop for Held {
    fn drop(&mut self) {
        let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
        *held = held.saturating_sub(1);
        drop(held);
        FREED.notify_all();
    }
}

/// Wait until another fragment may be forwarded, and count it.
pub(crate) fn take() -> Held {
    let limit = limit();
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    #[cfg(feature = "test-support")]
    let mut waited = false;
    while *held >= limit {
        #[cfg(feature = "test-support")]
        if !std::mem::replace(&mut waited, true) {
            probe::WAITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        held = FREED.wait(held).unwrap_or_else(|e| e.into_inner());
    }
    *held += 1;
    #[cfg(feature = "test-support")]
    probe::PEAK.fetch_max(*held, std::sync::atomic::Ordering::Relaxed);
    Held(())
}

/// Count another fragment only if one may be forwarded NOW, and answer
/// `None` at the limit: the form for a thread that holds places of its own
/// (`read::across`, where one thread hands out and combines), which gives
/// back what it holds rather than wait on itself.
pub(crate) fn try_take() -> Option<Held> {
    let limit = limit();
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if *held >= limit {
        #[cfg(feature = "test-support")]
        probe::REFUSALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    *held += 1;
    #[cfg(feature = "test-support")]
    probe::PEAK.fetch_max(*held, std::sync::atomic::Ordering::Relaxed);
    Some(Held(()))
}

/// How many forwarded fragments may be unread at once: HALF the soft
/// descriptor limit, never fewer than one and never more than [`MOST`].
///
/// Half, because the fragments are not the only files of an extraction:
/// each member in flight has its writer's file and its first volume, and
/// the walk has the volume it is in. At a limit too small for those the
/// extraction fails as it always has, with the system's own error; this
/// bound takes at least one fragment, so it never stops a set by itself.
pub(crate) fn limit() -> usize {
    limit_of(soft_descriptor_limit())
}

fn limit_of(soft: Option<u64>) -> usize {
    match soft {
        Some(soft) => usize::try_from(soft / 2).unwrap_or(MOST).clamp(1, MOST),
        None => MOST,
    }
}

/// The soft `RLIMIT_NOFILE`, where it is finite and can be read.
#[cfg(unix)]
#[allow(unsafe_code, clippy::useless_conversion)]
fn soft_descriptor_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable `rlimit`, which is all
    // `getrlimit` writes; it reads nothing of ours.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0;
    (ok && limit.rlim_cur != libc::RLIM_INFINITY)
        .then(|| u64::try_from(limit.rlim_cur).ok())
        .flatten()
}

/// Off Unix there is no such limit to read (a Windows process's handles
/// are bounded far above [`MOST`]).
#[cfg(not(unix))]
fn soft_descriptor_limit() -> Option<u64> {
    None
}

/// What a test reads of the bound (feature `test-support`).
#[cfg(feature = "test-support")]
pub(crate) mod probe {
    use std::sync::atomic::{AtomicU64, AtomicUsize};

    /// The most fragments ever forwarded and unread at once.
    pub(crate) static PEAK: AtomicUsize = AtomicUsize::new(0);
    /// How many times the walk had to wait for a worker.
    pub(crate) static WAITS: AtomicU64 = AtomicU64::new(0);
    /// How many times a thread that joins its own pieces was told to join
    /// some before it opened another volume ([`super::try_take`]).
    pub(crate) static REFUSALS: AtomicU64 = AtomicU64::new(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Half the soft limit, at least one, at most [`MOST`]; [`MOST`] where
    /// there is no finite limit.
    #[test]
    fn the_bound_is_half_the_soft_limit_inside_its_ends() {
        assert_eq!(limit_of(Some(256)), 128);
        assert_eq!(limit_of(Some(1024)), 512);
        assert_eq!(limit_of(Some(64)), 32);
        assert_eq!(limit_of(Some(3)), 1);
        assert_eq!(limit_of(Some(1)), 1);
        assert_eq!(limit_of(Some(0)), 1);
        assert_eq!(limit_of(Some(1 << 20)), MOST);
        assert_eq!(limit_of(Some(u64::MAX)), MOST);
        assert_eq!(limit_of(None), MOST);
    }

    /// The name this test is run by, alone, in a process of its own.
    const ALONE: &str = "RARKIT_TEST_FORWARDED_ALONE";

    fn held_now() -> usize {
        *HELD.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A place taken is given back when it is dropped, and a walk at the
    /// limit waits and goes on as soon as one is.
    ///
    /// The count is the PROCESS's, and other tests of this binary extract
    /// split members and move it while this one runs: until 10 Oct 2026
    /// the test compared the count with a figure it had read before, and
    /// went red whenever another test gave a place back, or took one, in
    /// between (seen 1 run in 3 of the whole binary, never alone). So it
    /// runs this binary again with this one test, where the count is its
    /// own and every figure is exact.
    ///
    /// Two threads at most, and no memory to speak of.
    #[test]
    fn a_dropped_place_lets_a_waiting_walk_go_on() {
        if std::env::var_os(ALONE).is_none() {
            let done = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "read::forwarded::tests::a_dropped_place_lets_a_waiting_walk_go_on",
                    "--exact",
                    "--test-threads=1",
                ])
                .env(ALONE, "1")
                .output()
                .unwrap();
            let said = String::from_utf8_lossy(&done.stdout);
            assert!(done.status.success(), "{done:?}");
            // The child ran the test, and did not pass over a name it
            // did not know.
            assert!(said.contains("1 passed"), "{said}");
            return;
        }
        assert_eq!(held_now(), 0);
        let one = take();
        let two = take();
        assert_eq!(held_now(), 2);
        drop(one);
        assert_eq!(held_now(), 1);
        drop(two);
        assert_eq!(held_now(), 0);
        #[cfg(unix)]
        a_walk_at_the_limit_waits_for_a_place();
    }

    /// With the soft descriptor limit at 4 the bound is 2: a third `take`
    /// waits while two places are held, and returns once one is dropped.
    /// Only ever called in the child process, whose limit it lowers.
    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn a_walk_at_the_limit_waits_for_a_place() {
        use std::time::Duration;
        let mut now = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `now` is a live, writable `rlimit`, which is all
        // `getrlimit` writes, and `setrlimit` only reads the one it is
        // given; the soft limit is lowered, which any process may do.
        let lowered = unsafe {
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut now) == 0 && {
                now.rlim_cur = 4;
                libc::setrlimit(libc::RLIMIT_NOFILE, &now) == 0
            }
        };
        assert!(lowered, "the soft descriptor limit could not be lowered");
        assert_eq!(limit(), 2);
        let one = take();
        let two = take();
        let (went_on, seen) = std::sync::mpsc::channel();
        let walk = std::thread::spawn(move || {
            let third = take();
            went_on.send(held_now()).unwrap();
            drop(third);
        });
        // At the limit the walk waits. A slow start can only make this
        // pass, never fail: the failure is a walk that did not wait.
        assert!(
            seen.recv_timeout(Duration::from_millis(300)).is_err(),
            "the walk went on with two places held and a bound of two"
        );
        drop(one);
        // Generous: a loaded box may be slow to run the woken thread.
        let held = seen
            .recv_timeout(Duration::from_secs(60))
            .expect("a dropped place did not let the waiting walk go on");
        assert_eq!(held, 2);
        walk.join().unwrap();
        drop(two);
        assert_eq!(held_now(), 0);
    }
}
