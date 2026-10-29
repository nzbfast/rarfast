//! What a filtered member's stream is made of, against another writer's,
//! counted rather than timed (the filter layout work, 28 Sep 2026): the
//! operations the apply stage walks and the arm each takes
//! (`internals::rar5::census` and `apply_shape`). A property of the
//! stream, the same on every box.
//!
//!     cargo run --release -p rarkit --example g_filter_layout_shape \
//!         --features h2-instruments -- a.rar b.rar

use rarkit::internals::rar5 as h2;

fn main() {
    for path in std::env::args().skip(1) {
        let archive = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let c = h2::census(&archive).unwrap_or_else(|e| panic!("{path}: {e}"));
        let shape = h2::apply_shape(&archive).unwrap_or_else(|e| panic!("{path}: {e}"));
        let (blocks, groups, _) =
            h2::plan_shape(&archive).unwrap_or_else(|e| panic!("{path}: {e}"));
        println!(
            "{path}: bytes {} blocks {blocks} groups {groups} ops {} symbols {} literals {} \
             matches {} repeats {} filters {}",
            c.bytes, c.operations, c.symbols, c.literals, c.matches, c.repeats, c.filters
        );
        for (name, count) in h2::APPLY_SHAPE_NAMES.iter().zip(shape) {
            println!("    {name:<36} {count:>12}");
        }
    }
}
