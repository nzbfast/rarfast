//! The threads the engine starts inside a `std::thread::scope`, and what it
//! does when the host will not start one.
//!
//! `Scope::spawn` PANICS when the operating system refuses a thread ("failed
//! to spawn thread"), and SPEC-API promise 2.1 is that no input makes the
//! engine panic. The refusal is not rare where it matters: under a finite
//! `RLIMIT_AS` on glibc Linux every thread maps its stack and a 64 MiB malloc
//! arena before it touches a page, so a stated `-mt16` under `ulimit -v`
//! 1 GiB ran out of address space in thread creation and exited 101 before
//! a byte was decoded (measured 30 Sep 2026).
//!
//! So every scoped spawn on the read path goes through [`scoped_with`], which
//! answers a refusal by handing back what the thread would have been given.
//! What the caller does with it is the caller's: a pool runs narrower, and a
//! helper's work runs on the calling thread. Nothing is retried and nothing
//! waits for a thread to become available, since a host that refused one has
//! said what it can hold.
//!
//! Under `test-support` a test can refuse spawns on purpose
//! ([`crate::probe::allow_spawns`]). The allowance is carried into every
//! thread spawned here, so the one test sees the refusals wherever in the
//! operation they fall; nothing outside a test that sets it is touched.

use std::sync::{Arc, Mutex};
use std::thread::{Scope, ScopedJoinHandle};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Start `work(state)` on a scoped thread, or hand `state` back unused when
/// the host will not start one.
///
/// The state travels through a cell rather than inside the closure because
/// a closure that `Builder::spawn_scoped` refused is dropped with everything
/// it captured, and the caller needs those values to carry on without the
/// thread. The cell costs one allocation and one uncontended lock per
/// spawn, beside a thread start measured in tens of microseconds.
pub(crate) fn scoped_with<'scope, 'env, S, T>(
    scope: &'scope Scope<'scope, 'env>,
    state: S,
    work: impl FnOnce(S) -> T + Send + 'scope,
) -> Result<ScopedJoinHandle<'scope, T>, S>
where
    S: Send + 'scope,
    T: Send + 'scope,
{
    #[cfg(feature = "test-support")]
    let inherited = match allowance::spend() {
        Some(inherited) => inherited,
        None => return Err(state),
    };
    let cell = Arc::new(Mutex::new(Some(state)));
    let theirs = Arc::clone(&cell);
    let spawned = std::thread::Builder::new().spawn_scoped(scope, move || {
        #[cfg(feature = "test-support")]
        allowance::inherit(inherited);
        let state = lock(&theirs)
            .take()
            .expect("the state is handed over exactly once");
        drop(theirs);
        work(state)
    });
    match spawned {
        Ok(handle) => Ok(handle),
        Err(_) => Err(lock(&cell)
            .take()
            .expect("a thread that never started took nothing")),
    }
}

/// [`scoped_with`] for a closure that carries its own state: a refused
/// closure comes back whole, to be run on the calling thread.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn scoped<'scope, 'env, F, T>(
    scope: &'scope Scope<'scope, 'env>,
    work: F,
) -> Result<ScopedJoinHandle<'scope, T>, F>
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    scoped_with(scope, work, |work| work())
}

/// Start `work` on a thread that is NOT scoped, for a team kept across
/// the ranges of one operation (`read::team`), or answer `None` when the
/// host will not start one. The handle is the caller's to join: a kept
/// thread is waited for by name when its team ends. The same refusal and
/// the same test allowance as [`scoped_with`].
#[cfg(feature = "parallel")]
pub(crate) fn kept(work: impl FnOnce() + Send + 'static) -> Option<std::thread::JoinHandle<()>> {
    #[cfg(feature = "test-support")]
    let inherited = allowance::spend()?;
    std::thread::Builder::new()
        .spawn(move || {
            #[cfg(feature = "test-support")]
            allowance::inherit(inherited);
            work()
        })
        .ok()
}

/// The spawns a test still allows, shared by the thread that set it and
/// every thread [`scoped_with`] starts from there, and how many it refused.
#[cfg(feature = "test-support")]
pub(crate) mod allowance {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Default)]
    pub(crate) struct Allowance {
        left: AtomicUsize,
        refused: AtomicUsize,
    }

    thread_local! {
        static LEFT: RefCell<Option<Arc<Allowance>>> = const { RefCell::new(None) };
    }

    /// Allow this thread, and every thread spawned from it through
    /// [`super::scoped_with`], `n` more spawns in all; `None` lifts it.
    pub(crate) fn set(n: Option<usize>) {
        let _ = LEFT.try_with(|left| {
            *left.borrow_mut() = n.map(|n| {
                Arc::new(Allowance {
                    left: AtomicUsize::new(n),
                    refused: AtomicUsize::new(0),
                })
            })
        });
    }

    /// How many spawns the allowance this thread holds has refused.
    pub(crate) fn refused() -> usize {
        LEFT.try_with(|left| {
            left.borrow()
                .as_ref()
                .map_or(0, |a| a.refused.load(Ordering::Acquire))
        })
        .unwrap_or(0)
    }

    /// Spend one spawn: `None` when the allowance is spent, else what the
    /// new thread inherits.
    pub(crate) fn spend() -> Option<Option<Arc<Allowance>>> {
        let held = LEFT.try_with(|left| left.borrow().clone()).unwrap_or(None);
        let Some(held) = held else {
            return Some(None);
        };
        let spent = held
            .left
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok();
        if !spent {
            held.refused.fetch_add(1, Ordering::AcqRel);
            return None;
        }
        Some(Some(held))
    }

    pub(crate) fn inherit(held: Option<Arc<Allowance>>) {
        let _ = LEFT.try_with(|slot| *slot.borrow_mut() = held);
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;

    #[test]
    fn a_refused_spawn_hands_its_state_back_and_runs_nothing() {
        allowance::set(Some(0));
        let ran = std::sync::atomic::AtomicBool::new(false);
        let back = std::thread::scope(|scope| {
            scoped_with(scope, vec![1u8, 2, 3], |v| {
                ran.store(true, std::sync::atomic::Ordering::SeqCst);
                v.len()
            })
            .err()
        });
        let refused = allowance::refused();
        allowance::set(None);
        assert_eq!(back, Some(vec![1, 2, 3]));
        assert_eq!(refused, 1);
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn an_allowance_is_shared_with_the_threads_it_starts() {
        allowance::set(Some(2));
        let (outer, inner) = std::thread::scope(|scope| {
            let handle = scoped(scope, || {
                // The one spawn left is this thread's to spend, and then
                // the allowance is gone here too.
                std::thread::scope(|scope| {
                    let first = scoped(scope, || 7).map(|h| h.join().unwrap()).ok();
                    let second = scoped(scope, || 8).map(|h| h.join().unwrap()).ok();
                    (first, second)
                })
            })
            .ok()
            .expect("the first spawn is allowed");
            (handle.join().unwrap(), scoped(scope, || 9).is_err())
        });
        allowance::set(None);
        assert_eq!(outer, (Some(7), None));
        assert!(inner, "the allowance was spent across both threads");
    }

    #[test]
    fn with_no_allowance_set_every_spawn_starts() {
        let got = std::thread::scope(|scope| {
            (0..4)
                .map(|k| scoped(scope, move || k).ok().expect("started"))
                .map(|h| h.join().unwrap())
                .sum::<i32>()
        });
        assert_eq!(got, 6);
    }
}
