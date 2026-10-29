//! The filter pass's price on a filtered member's extract, by SUBTRACTION
//! inside one process (the filter layout work, 28 Sep 2026).
//! UNTIMED: a direction, never a verdict.
//!
//! For each archive, rounds rotated, `extract_counting` (the shipped
//! decode into a counting sink) under three arms of
//! `rar5_lz::filters::arms`: `ship` what ships, `notx` every record queued
//! and every span copied out but no transform run, `nofilt` every record
//! dropped. `ship - notx` is the transform's price on the critical path,
//! `notx - nofilt` the hold and copy path's, and `nofilt` the decode of
//! the filtered stream alone.
//!
//!     cargo run --release -p rarkit --example g_filter_layout_split \
//!         --features h2-filter-arms,bench-internals -- 15 a.rar b.rar

use std::time::Instant;

use rarkit::internals::rar5 as h2;

fn main() {
    let mut args = std::env::args().skip(1);
    let rounds: usize = args
        .next()
        .and_then(|r| r.parse().ok())
        .expect("usage: ROUNDS A.rar...");
    let paths: Vec<String> = args.collect();
    const ARMS: [(&str, u8); 3] = [("ship", 0), ("notx", 1), ("nofilt", 2)];
    for path in paths {
        let archive = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut walls = [const { Vec::new() }; 3];
        for round in 0..rounds + 1 {
            for turn in 0..ARMS.len() {
                let arm = (round + turn) % ARMS.len();
                h2::set_filter_arm(ARMS[arm].1);
                let started = Instant::now();
                let bytes = h2::extract_counting(&archive, None).expect("extract");
                let wall = started.elapsed().as_secs_f64() * 1e3;
                std::hint::black_box(bytes);
                // Round 0 warms the pool and the page cache and is dropped.
                if round > 0 {
                    walls[arm].push(wall);
                }
            }
        }
        h2::set_filter_arm(0);
        let median = |v: &mut Vec<f64>| {
            v.sort_by(|a, b| a.total_cmp(b));
            v[v.len() / 2]
        };
        let [ship, notx, nofilt] = walls.each_mut().map(median);
        println!(
            "{path}: ship {ship:.2} ms, notx {notx:.2}, nofilt {nofilt:.2} | transform {:.2}, \
             copy path {:.2}",
            ship - notx,
            notx - nofilt
        );
    }
}
