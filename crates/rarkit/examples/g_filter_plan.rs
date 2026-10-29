//! What spec G 3.8.2's detection chose for a file, region by region, and
//! why: the kept span's transform, and every candidate's probe total in
//! bits beside the unfiltered one. A diagnostic for the filter count
//! (the filter count script), not a gate leg.
//!
//!     cargo run --release --features bench-internals --example g_filter_plan -- FILE [--totals | --time | --read]

use rarkit::internals::writers::{filter_plan, filter_probe_totals};
use std::collections::BTreeMap;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: g_filter_plan FILE [--totals | --time | --read]");
    let flag = args.next();
    let totals = flag.as_deref() == Some("--totals");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    if flag.as_deref() == Some("--read") {
        // The baseline a `--time` run's instruction count is read against:
        // the same process and the same file read, and no detection.
        println!("{path}: {} bytes read", std::hint::black_box(&bytes).len());
        return;
    }
    if flag.as_deref() == Some("--time") {
        // Detection alone, on however many threads rayon is given
        // (RAYON_NUM_THREADS=1 for the per-byte cost).
        // `REPEAT=n` runs it n times, for a profiler to sample; the figure
        // printed is the last run's.
        let repeat: usize = std::env::var("REPEAT")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1);
        for _ in 1..repeat {
            std::hint::black_box(filter_plan(&bytes));
        }
        let started = std::time::Instant::now();
        let plan = filter_plan(&bytes);
        let wall = started.elapsed().as_secs_f64();
        println!(
            "{path}: detect {:.1} ms, {:.2} ns a byte, {} spans",
            wall * 1e3,
            wall * 1e9 / bytes.len() as f64,
            plan.len()
        );
        return;
    }
    let plan = filter_plan(&bytes);
    let regions = bytes.len().div_ceil(256 << 10);
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for (_, _, kind) in &plan {
        *kinds.entry(kind.clone()).or_default() += 1;
    }
    println!(
        "{path}: {} bytes, {regions} regions, {} filtered: {kinds:?}",
        bytes.len(),
        plan.len()
    );
    if totals {
        for index in 0..regions {
            let start = index * (256 << 10);
            let end = (start + 0x3ffff).min(bytes.len());
            let row = filter_probe_totals(&bytes[start..end], start as u64);
            let plain = row[0].1 as f64;
            let cells: Vec<String> = row
                .iter()
                .map(|(kind, bits)| format!("{kind}={:.3}", *bits as f64 / plain))
                .collect();
            let kept = plan
                .iter()
                .find(|(s, _, _)| *s == start)
                .map_or("-", |(_, _, k)| k);
            println!("region {index} kept {kept}: {}", cells.join(" "));
        }
    }
}
