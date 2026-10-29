//! How far back a RAR 5 archive's fresh matches reach, and how many of the
//! far ones the far-copy prefetch's gate would hint, counted rather than
//! timed.
//!
//! The dictionary work found `rarfast x` of a solid 1 GiB text set 1 to 7
//! percent SLOWER at a 32 MiB dictionary than at 2 MiB, at less CPU, and
//! the walking thread's samples sit in the apply walk. A larger dictionary
//! moves match sources past the caches; this prints by how much, per
//! distance band, so a lever is argued from the stream and not a guess.
//!
//! Usage: `cargo run --release -p rarkit --features
//! bench-internals,h2-locality-census --example h2_window_reach --
//! ARCHIVE...`. A count, the same on every box.

#[cfg(not(all(feature = "bench-internals", feature = "h2-locality-census")))]
fn main() {
    eprintln!("REFUSING: build with --features bench-internals,h2-locality-census.");
    std::process::exit(2);
}

#[cfg(all(feature = "bench-internals", feature = "h2-locality-census"))]
fn main() {
    use rarkit::internals::rar5::{reach, REACH_BANDS};
    let names: Vec<String> = std::iter::once("1 B".to_string())
        .chain(REACH_BANDS.iter().map(|&e| {
            if e >= 1 << 20 {
                format!("{} MiB", e >> 20)
            } else {
                format!("{} KiB", e >> 10)
            }
        }))
        .collect();
    for path in std::env::args().skip(1) {
        let archive = std::fs::read(&path).expect("the archive reads");
        let r = reach(&archive).expect("the census walks");
        let matches: u64 = r[6..13].iter().sum();
        let bytes: u64 = r[13..20].iter().sum();
        println!("=== {path}");
        println!(
            "  members {} (skipped {}), tapes {} (gate admits {}), ops {}, repeats {}, fresh matches {}",
            r[0], r[1], r[2], r[3], r[4], r[5], matches
        );
        for (band, name) in names.iter().enumerate() {
            println!(
                "  from {:>7}: {:>11} matches {:5.1}%, {:>12} bytes {:5.1}%",
                name,
                r[6 + band],
                100.0 * r[6 + band] as f64 / matches.max(1) as f64,
                r[13 + band],
                100.0 * r[13 + band] as f64 / bytes.max(1) as f64
            );
        }
        println!(
            "  far matches (from 256 KiB) in admitted tapes {}, in refused tapes {}",
            r[20], r[21]
        );
    }
}
