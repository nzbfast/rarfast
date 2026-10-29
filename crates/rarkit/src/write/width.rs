//! Where a write's pool work runs, so that `-mt N` is at most N helper
//! threads beside the caller's own (SPEC-API 7.2 at
//! `WriteOptions::workers`).
//!
//! A write hands work to a rayon pool in several places: the worker team's
//! crews, the encoder's parse waves and tree walkers, the filter detection,
//! the solid batch beside the writing thread, and the recovery record's
//! fold. Each of those takes the pool it is called from, and the caller's
//! pool is the process's global one unless the caller installed another.
//! So a caller who set `workers = Some(2)` on a box whose pool is eighteen
//! wide got eighteen helpers at once, whatever each site's own width
//! figure said: counted 30 Sep 2026 on this repository's library writer,
//! the high-water was 17 to 18 helpers at `-mt1`, `-mt2` and `-mt4` on
//! every compressed shape, and 25 where the BLAKE2sp team ran beside it.
//!
//! The rule here is one sentence: **a write's pool work runs on a pool no
//! wider than N.** Where the caller's pool is already no wider (the
//! command line sizes the global pool to `-mt`, and `workers: None` means
//! the caller's pool by definition), nothing moves and nothing is built.
//! Where it is wider, the write's work runs on a pool of exactly N threads
//! instead, built once per width and kept, like the global pool, for the
//! life of the process. The threads it spawns inside that pool, walkers
//! included, find it as their pool without being told, because rayon
//! gives a task the pool it runs on.
//!
//! Two entry points hand work to the pool from the calling thread, and
//! both route here: [`on_pool`], which runs a closure there and waits
//! (every encoder call the writer makes, and the recovery record's
//! encode), and [`scope_here`], which spawns into the pool while the
//! calling thread goes on writing (the worker team's round and the solid
//! batch). A call from a thread that is already one of the pool's own
//! runs where it is.
//!
//! What this does NOT bound is a thread started outside any pool: the
//! stored copy's stages (bounded by `engine::Stages::plan`), the BLAKE2sp
//! team's parked threads (bounded by the allowance each digest is built
//! with, `engine::Run::digest_threads`), the key derivation's second
//! thread, and the recovery encode's own team (given at most N). Those
//! are each bounded where they start.

#[cfg(feature = "parallel")]
use std::cell::{Cell, RefCell};
#[cfg(feature = "parallel")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "parallel")]
thread_local! {
    /// The `workers` figure of the write this thread is running, while
    /// [`enter`]'s guard lives: `None` outside a write, `Some(None)` for a
    /// write whose `workers` is `None` (the caller's pool).
    static WANT: Cell<Option<Option<usize>>> = const { Cell::new(None) };
    /// The narrowed pool this thread's write runs on, once one was needed
    /// ([`narrow`]). Built lazily, so a write that never reaches the pool
    /// never reads the global pool's width, which is what builds it
    /// (spec G 7.3; `tests/write_allocation.rs`).
    static NARROW: RefCell<Option<Arc<rayon::ThreadPool>>> = const { RefCell::new(None) };
    /// Whether this thread is inside [`on_pool`] or [`scope_here`] now, so
    /// that a nested call counts the pool once (the census, `cfg(test)`).
    static LENT: Cell<bool> = const { Cell::new(false) };
}

/// Narrowed pools already built, one per width. A pool's idle threads are
/// parked, which is not a helper (a thread counts while it runs this
/// write's work), and building one costs a thread spawn per worker, which
/// a writer asked for thousands of small archives would otherwise pay per
/// archive.
#[cfg(feature = "parallel")]
static POOLS: Mutex<Vec<Arc<rayon::ThreadPool>>> = Mutex::new(Vec::new());

/// Marks this thread as running a write whose `workers` is `workers`, for
/// as long as the guard lives. `engine::run` takes it first.
pub(super) fn enter(workers: Option<usize>) -> Entered {
    #[cfg(feature = "parallel")]
    {
        let before = WANT.with(|want| want.replace(Some(workers)));
        let pool = NARROW.with(|pool| pool.borrow_mut().take());
        Entered { before, pool }
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = workers;
        Entered {}
    }
}

/// What [`enter`] replaced, put back when the write ends.
pub(super) struct Entered {
    #[cfg(feature = "parallel")]
    before: Option<Option<usize>>,
    #[cfg(feature = "parallel")]
    pool: Option<Arc<rayon::ThreadPool>>,
}

impl Drop for Entered {
    fn drop(&mut self) {
        #[cfg(feature = "parallel")]
        {
            WANT.with(|want| want.set(self.before));
            let pool = self.pool.take();
            NARROW.with(|narrow| *narrow.borrow_mut() = pool);
        }
    }
}

/// The narrowed pool this write runs on, building or finding it on first
/// use, or `None` where the caller's pool is no wider than `workers`.
#[cfg(feature = "parallel")]
fn narrow() -> Option<Arc<rayon::ThreadPool>> {
    let want = WANT.with(Cell::get).flatten()?.max(1);
    if let Some(pool) = NARROW.with(|pool| pool.borrow().clone()) {
        return Some(pool);
    }
    // A thread already on a narrowed pool is on the write's pool: the
    // crews and every task spawned inside them.
    if rayon::current_num_threads() <= want {
        return None;
    }
    let pool = {
        let mut pools = POOLS.lock().unwrap_or_else(|e| e.into_inner());
        match pools.iter().find(|pool| pool.current_num_threads() == want) {
            Some(pool) => Arc::clone(pool),
            None => {
                let built = rayon::ThreadPoolBuilder::new()
                    .num_threads(want)
                    .thread_name(|index| format!("rarkit-write-{index}"))
                    .build()
                    .ok()
                    .map(Arc::new)?;
                pools.push(Arc::clone(&built));
                built
            }
        }
    };
    NARROW.with(|narrow| *narrow.borrow_mut() = Some(Arc::clone(&pool)));
    Some(pool)
}

/// The width of the pool this write's work runs on: N where the caller's
/// pool is wider than N, and the caller's pool otherwise. One without the
/// `parallel` feature. Reading it builds the global pool when nothing has.
pub(super) fn pool_width() -> usize {
    #[cfg(feature = "parallel")]
    {
        let caller = rayon::current_num_threads().max(1);
        match WANT.with(Cell::get).flatten() {
            Some(want) => caller.min(want.max(1)),
            None => caller,
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}

/// Runs `work` on this write's pool and waits for it: on the narrowed pool
/// when there is one and this thread is not already one of its workers,
/// and right here otherwise, where any pool work it starts goes to the
/// caller's pool, which is then no wider than N.
pub(super) fn on_pool<R: Send>(work: impl FnOnce() -> R + Send) -> R {
    #[cfg(feature = "parallel")]
    {
        let _lent = lend();
        match narrow() {
            Some(pool) if pool.current_thread_index().is_none() => pool.install(work),
            _ => work(),
        }
    }
    #[cfg(not(feature = "parallel"))]
    {
        work()
    }
}

/// `rayon::in_place_scope` on this write's pool: `op` runs on this thread,
/// and what it spawns runs on the narrowed pool when there is one, on the
/// caller's otherwise.
#[cfg(feature = "parallel")]
pub(super) fn scope_here<'scope, R>(op: impl FnOnce(&rayon::Scope<'scope>) -> R) -> R {
    let _lent = lend();
    match narrow() {
        Some(pool) => pool.in_place_scope(op),
        None => rayon::in_place_scope(op),
    }
}

/// Hands `task` to this write's pool and returns at once: the narrowed
/// pool when there is one, the caller's otherwise. Nothing waits for it
/// here, so the caller keeps [`lend`]'s guard for as long as such a task
/// may run, and learns that it ended from the task itself (the segment
/// team's rolling hand-off, `engine::Roll`).
#[cfg(feature = "parallel")]
pub(super) fn spawn(task: impl FnOnce() + Send + 'static) {
    match narrow() {
        Some(pool) => pool.spawn(task),
        None => rayon::spawn(task),
    }
}

/// Whether the calling thread is one of the threads [`spawn`] hands its
/// tasks to. Such a thread may not sleep until a task of its own ends: on
/// a pool of one it is the only thread that could run it.
#[cfg(feature = "parallel")]
pub(super) fn on_own_pool() -> bool {
    match narrow() {
        Some(pool) => pool.current_thread_index().is_some(),
        None => rayon::current_thread_index().is_some(),
    }
}

/// Marks the calling thread as having lent the pool until the guard drops
/// ([`lent`]). The census (`cfg(test)`) counts the calling thread's first
/// lending as the pool's whole width in helpers for as long as it lasts,
/// since whatever the write spawned into it may fill it; a nested lending,
/// and one from a thread that is itself a pool's, adds nothing, the pool
/// being counted already.
#[cfg(feature = "parallel")]
pub(super) fn lend() -> Lent {
    let first = !LENT.with(|lent| lent.replace(true));
    #[cfg(test)]
    let held = (first && rayon::current_thread_index().is_none())
        .then(|| super::engine::hold(pool_width()));
    Lent {
        first,
        #[cfg(test)]
        _held: held,
    }
}

#[cfg(feature = "parallel")]
pub(super) struct Lent {
    first: bool,
    #[cfg(test)]
    _held: Option<super::engine::Held>,
}

#[cfg(feature = "parallel")]
impl Drop for Lent {
    fn drop(&mut self) {
        if self.first {
            LENT.with(|lent| lent.set(false));
        }
    }
}

/// Whether the calling thread has lent this write's pool now: the worker
/// team's round or the solid batch is running beside it, so the pool is
/// busy and a digest this thread takes gets no team of its own
/// (`engine::Run::digest_threads`).
pub(super) fn lent() -> bool {
    #[cfg(feature = "parallel")]
    {
        LENT.with(Cell::get)
    }
    #[cfg(not(feature = "parallel"))]
    {
        false
    }
}
