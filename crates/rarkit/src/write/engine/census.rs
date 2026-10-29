//! The helper census: how many helper threads a write has alive at once,
//! and which of its paths a span took, for the tests to read. `cfg(test)`
//! alone.

use super::*;

// The helper threads live at once, and the most there have been, for the
// write the calling thread is running: the helper count, which the tests
// read as a high-water. The count belongs to the CALLING thread, so tests
// running beside each other do not see each other's helpers. `cfg(test)`
// alone.
#[cfg(test)]
thread_local! {
    pub(crate) static HELPERS: std::sync::Arc<HelperCensus> =
        std::sync::Arc::new(HelperCensus::default());
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct HelperCensus {
    pub(super) live: std::sync::atomic::AtomicUsize,
    pub(super) peak: std::sync::atomic::AtomicUsize,
    /// Chains ahead begun since the last reset: one a member that was
    /// given a chain. The writing thread decides each from the members'
    /// sizes and the helper count, so the figure does not follow the
    /// schedule, where the peak of helpers ALIVE AT ONCE does: a chain
    /// that ends before the next helper begins leaves a peak of one.
    pub(super) chains: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl HelperCensus {
    /// The most helpers alive at once since the last [`HelperCensus::reset`].
    pub(crate) fn peak(&self) -> usize {
        self.peak.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Chains ahead begun since the last [`HelperCensus::reset`].
    pub(crate) fn chains(&self) -> usize {
        self.chains.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn reset(&self) {
        self.peak.store(0, std::sync::atomic::Ordering::SeqCst);
        self.chains.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Helpers that `n` more threads may be at once, counted on the calling
/// thread's census for as long as the guard lives: a pool the write lent
/// (`width::on_pool`, `width::scope_here`, at the pool's whole width) or a
/// BLAKE2sp team (its allowance less the hashing thread's own). An upper
/// bound on what they run at any instant, which is what the census holds
/// to N.
#[cfg(test)]
pub(crate) fn hold(n: usize) -> Held {
    hold_on(&HELPERS.with(std::sync::Arc::clone), n)
}

/// [`hold`] on a census named rather than this thread's.
#[cfg(test)]
pub(super) fn hold_on(census: &std::sync::Arc<HelperCensus>, n: usize) -> Held {
    use std::sync::atomic::Ordering::SeqCst;
    let now = census.live.fetch_add(n, SeqCst) + n;
    census.peak.fetch_max(now, SeqCst);
    Held(std::sync::Arc::clone(census), n)
}

/// What [`hold`] counted, uncounted when it drops.
#[cfg(test)]
pub(crate) struct Held(std::sync::Arc<HelperCensus>, usize);

#[cfg(test)]
impl Drop for Held {
    fn drop(&mut self) {
        self.0
            .live
            .fetch_sub(self.1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One helper thread's life, counted from its first instruction to its
/// last.
#[cfg(test)]
pub(super) struct Live<'c>(&'c HelperCensus);

#[cfg(test)]
impl<'c> Live<'c> {
    pub(super) fn enter(census: &'c HelperCensus) -> Live<'c> {
        use std::sync::atomic::Ordering::SeqCst;
        let now = census.live.fetch_add(1, SeqCst) + 1;
        census.peak.fetch_max(now, SeqCst);
        Live(census)
    }
}

#[cfg(test)]
impl Drop for Live<'_> {
    fn drop(&mut self) {
        self.0
            .live
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

// How many spans this thread has READ AHEAD, so the tests can say the path
// they hold to the serial one was taken. `cfg(test)` alone.
#[cfg(test)]
thread_local! {
    pub(crate) static AHEAD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// How many spans this thread has copied with their digest BESIDE the copy,
// so the tests can say the path they hold to the serial one was taken.
// `cfg(test)` alone: no bench or shipped build carries it.
#[cfg(test)]
thread_local! {
    pub(crate) static BESIDE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
