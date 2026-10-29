//! How a RAR 5 member's BLOCKS are laid out, counted rather than timed
//! (the unrar-friendly writer work).
//!
//! Reference unrar extracts some rarkit archives far slower than rar's of
//! the same input. This prints what separates the two streams at the block
//! level: how many blocks, their packed sizes, how many carry tables, what
//! the tables cost and how deep their codes run. Every figure is a
//! property of the stream, the same on every box, and the archives may
//! come from any writer: they are read by rarkit's own parser.
//!
//!     cargo run --release -p rarkit --features h2-instruments \
//!         --example g_unrar_block_shape -- [-v] a.rar b.rar

use rarkit::internals::rar5::{block_shapes, members, BlockShape};

fn deepest(histogram: &[u32; 16]) -> usize {
    (1..16).rev().find(|&l| histogram[l] > 0).unwrap_or(0)
}

fn main() {
    let mut verbose = false;
    for arg in std::env::args().skip(1) {
        if arg == "-v" {
            verbose = true;
            continue;
        }
        let archive = std::fs::read(&arg).expect("read archive");
        for (index, member) in members(&archive).iter().enumerate() {
            if member.method == 0 || member.directory {
                println!(
                    "{arg} #{index}: stored or directory, {} bytes",
                    member.unpacked
                );
                continue;
            }
            let shapes: Vec<BlockShape> = block_shapes(&member.packed, member.algorithm);
            let mut sizes: Vec<usize> = shapes.iter().map(|s| s.packed).collect();
            sizes.sort_unstable();
            let with_tables = shapes.iter().filter(|s| s.has_tables).count();
            let table_bits: usize = shapes.iter().map(|s| s.table_bits).sum();
            let mut main_deep = [0usize; 16];
            let mut flat_main = 0usize;
            for s in shapes.iter().filter(|s| s.has_tables) {
                main_deep[deepest(&s.histograms[0])] += 1;
                let used: u32 = s.histograms[0][1..].iter().sum();
                if used > 0 && s.histograms[0][8] as f64 >= 0.9 * f64::from(used) {
                    flat_main += 1;
                }
            }
            let pct = |q: usize| {
                sizes
                    .get((sizes.len().saturating_sub(1)) * q / 100)
                    .copied()
                    .unwrap_or(0)
            };
            println!(
                "{arg} #{index}: window {} unpacked {} packed {} blocks {} with tables {} | block bytes min {} p10 {} p50 {} p90 {} max {} | table bytes {} | main tables mostly 8 bit {} | deepest main code by block {:?}",
                member.window,
                member.unpacked,
                member.packed.len(),
                shapes.len(),
                with_tables,
                sizes.first().copied().unwrap_or(0),
                pct(10),
                pct(50),
                pct(90),
                sizes.last().copied().unwrap_or(0),
                table_bits / 8,
                flat_main,
                main_deep
                    .iter()
                    .enumerate()
                    .filter(|(_, &n)| n > 0)
                    .map(|(l, &n)| format!("{l}:{n}"))
                    .collect::<Vec<_>>(),
            );
            if verbose {
                for (n, s) in shapes.iter().enumerate() {
                    println!(
                        "  block {n}: packed {} tables {} table bytes {} last {} main {:?} dist {:?} align {:?} len {:?}",
                        s.packed,
                        s.has_tables,
                        s.table_bits / 8,
                        s.is_last,
                        s.histograms[0],
                        s.histograms[1],
                        s.histograms[2],
                        s.histograms[3]
                    );
                }
            }
        }
    }
}
