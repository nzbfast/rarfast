//! The tree walk's COUNT (feature `tree-walk-census`): what one position of the
//! level 4 and 5 walk costs, by kind of work, and how often a walker
//! touches a cache line another walker wrote last.
//!
//! A lab instrument and nothing else. It is a feature of its own under the
//! measured-arm rule (`Cargo.toml`, `h2-apply-arms`): no shipped build and
//! no gate binary turns it on, and with it off not one call below is
//! compiled. With it on the walk is SLOWER, by the line table's atomic
//! swaps above all, so a wall figure from a census build means nothing;
//! the counts are the product.
//!
//! A line is SHARED when the walker touching it is not the walker that
//! last wrote it: that is a line that has to come from another core's
//! cache. The line table hashes lines into a fixed table, so a collision
//! can hide an event or invent one; at 16 Mi entries against the tree's
//! few million lines it is noise.
//!
//! Counts gather per thread and fold into process totals when a bin or a
//! serial range finishes, so the hot loop touches no shared counter. The
//! totals print to stderr when the process's last finder is dropped.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// What one thread has counted since it last folded.
#[derive(Default, Clone, Copy)]
pub(crate) struct Tally {
    /// Positions that descended (four bytes ahead of them in range).
    pub(crate) positions: u64,
    /// Nodes a descent visited (each step that passed the window test).
    pub(crate) visits: u64,
    /// Calls of the prefix comparison.
    pub(crate) compares: u64,
    /// Bytes the comparisons established beyond where they started.
    pub(crate) compared_bytes: u64,
    /// Eight-byte words the comparisons loaded from each side.
    pub(crate) compared_words: u64,
    /// Stores into `son`.
    pub(crate) son_stores: u64,
    /// Of those, stores that wrote the value the slot already held: a step
    /// in the same direction as the one before it.
    pub(crate) son_same: u64,
    /// Stores into the hint slots.
    pub(crate) hint_stores: u64,
    /// Exits: empty subtree, cut exhausted, out of window, cap reached.
    pub(crate) exit_empty: u64,
    pub(crate) exit_cut: u64,
    pub(crate) exit_window: u64,
    pub(crate) exit_nice: u64,
    /// Line events: a store (or a load) to a line whose last writer was
    /// another walker, by structure.
    pub(crate) son_store_shared: u64,
    pub(crate) son_load_shared: u64,
    pub(crate) head_store_shared: u64,
    pub(crate) head_load_shared: u64,
    pub(crate) hint_store_shared: u64,
    /// Nanoseconds: dealing chunks, walking bins (summed over walkers), the
    /// parallel walks' walls and those walls times their walker counts, so
    /// `bin_ns / walker_ns` is how busy the walkers were; and the serial
    /// arm's walk.
    pub(crate) deal_ns: u64,
    pub(crate) bin_ns: u64,
    pub(crate) walk_ns: u64,
    pub(crate) walker_ns: u64,
    pub(crate) walks: u64,
    pub(crate) serial_ns: u64,
    pub(crate) serial_positions: u64,
}

const FIELDS: usize = 24;

impl Tally {
    fn as_array(&self) -> [u64; FIELDS] {
        [
            self.positions,
            self.visits,
            self.compares,
            self.compared_bytes,
            self.compared_words,
            self.son_stores,
            self.son_same,
            self.hint_stores,
            self.exit_empty,
            self.exit_cut,
            self.exit_window,
            self.exit_nice,
            self.son_store_shared,
            self.son_load_shared,
            self.head_store_shared,
            self.head_load_shared,
            self.hint_store_shared,
            self.deal_ns,
            self.bin_ns,
            self.walk_ns,
            self.walker_ns,
            self.walks,
            self.serial_ns,
            self.serial_positions,
        ]
    }
}

const NAMES: [&str; FIELDS] = [
    "positions",
    "visits",
    "compares",
    "compared_bytes",
    "compared_words",
    "son_stores",
    "son_same",
    "hint_stores",
    "exit_empty",
    "exit_cut",
    "exit_window",
    "exit_nice",
    "son_store_shared",
    "son_load_shared",
    "head_store_shared",
    "head_load_shared",
    "hint_store_shared",
    "deal_ns",
    "bin_ns",
    "walk_ns",
    "walker_ns",
    "walks",
    "serial_ns",
    "serial_positions",
];

fn totals() -> &'static [AtomicU64; FIELDS] {
    static TOTALS: OnceLock<[AtomicU64; FIELDS]> = OnceLock::new();
    TOTALS.get_or_init(|| std::array::from_fn(|_| AtomicU64::new(0)))
}

thread_local! {
    static TALLY: RefCell<Tally> = RefCell::new(Tally::default());
    static WALKER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Count into this thread's tally.
#[inline]
pub(crate) fn with(f: impl FnOnce(&mut Tally)) {
    TALLY.with(|t| f(&mut t.borrow_mut()));
}

/// Fold this thread's tally into the process totals.
pub(crate) fn fold() {
    let tally = TALLY.with(|t| std::mem::take(&mut *t.borrow_mut()));
    for (total, value) in totals().iter().zip(tally.as_array()) {
        total.fetch_add(value, Ordering::Relaxed);
    }
}

/// Which walker this thread is for the line table: a rayon worker's index
/// plus one, or zero off the pool.
pub(crate) fn set_walker() {
    #[cfg(feature = "parallel")]
    let id = rayon::current_thread_index().map_or(0, |index| index as u32 + 1);
    #[cfg(not(feature = "parallel"))]
    let id = 0;
    WALKER.with(|w| w.set(id));
}

/// The line table: for each (hashed) cache line, the line and the walker
/// that last wrote it.
fn lines() -> &'static [AtomicU64] {
    static LINES: OnceLock<Vec<AtomicU64>> = OnceLock::new();
    LINES.get_or_init(|| {
        let mut v = Vec::new();
        v.resize_with(1 << 24, || AtomicU64::new(0));
        v
    })
}

fn slot_of(line: usize) -> usize {
    // Hashed as a `u64` whatever the pointer width: the multiplier does
    // not fit a 32-bit `usize`, and written on `usize` this lab feature
    // stopped an `--all-features` build for a 32-bit target. The same
    // slot as before on a 64-bit one.
    let hashed = (line as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - 24);
    hashed as usize & ((1 << 24) - 1)
}

fn tag(line: usize) -> u64 {
    let walker = u64::from(WALKER.with(std::cell::Cell::get) & 0xFF);
    ((line as u64 & 0xFF_FFFF_FFFF) << 8) | walker
}

/// Which structure a line belongs to.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Son,
    Head,
    Hint,
}

/// A store to `address`: was its line last written by another walker?
#[inline]
pub(crate) fn store<T>(address: *const T, kind: Kind) {
    let line = address as usize >> 6;
    let new = tag(line);
    let old = lines()[slot_of(line)].swap(new, Ordering::Relaxed);
    let shared = old >> 8 == new >> 8 && (old & 0xFF) != (new & 0xFF);
    with(|t| match kind {
        Kind::Son => t.son_store_shared += u64::from(shared),
        Kind::Head => t.head_store_shared += u64::from(shared),
        Kind::Hint => t.hint_store_shared += u64::from(shared),
    });
}

/// A load from `address`: was its line last written by another walker, so
/// that it sits in another core's cache?
#[inline]
pub(crate) fn load<T>(address: *const T, kind: Kind) {
    let line = address as usize >> 6;
    let new = tag(line);
    let old = lines()[slot_of(line)].load(Ordering::Relaxed);
    let shared = old >> 8 == new >> 8 && (old & 0xFF) != (new & 0xFF);
    with(|t| match kind {
        Kind::Son => t.son_load_shared += u64::from(shared),
        Kind::Head => t.head_load_shared += u64::from(shared),
        Kind::Hint => {}
    });
}

/// Print the process totals, one `name value` pair each, on one line.
pub(crate) fn report() {
    fold();
    let mut line = String::from("TREE-CENSUS");
    for (name, total) in NAMES.iter().zip(totals().iter()) {
        line.push_str(&format!(" {name}={}", total.load(Ordering::Relaxed)));
    }
    eprintln!("{line}");
}
