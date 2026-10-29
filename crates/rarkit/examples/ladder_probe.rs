//! The incompressible sample's YIELD, block by block, so the threshold in
//! `encode::sample` is a number that was read off a histogram rather than
//! guessed at.
//!
//! `ladder_probe <file>...` prints, for each file, the distribution of
//! four byte repeats per thousand sampled positions over its 256 KiB parse
//! blocks: the minimum, the deciles and the share of blocks that fall
//! under the shipped threshold.

use rarkit::internals::rar20;

fn main() {
    let files: Vec<String> = std::env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("usage: ladder_probe <file>...");
        std::process::exit(2);
    }
    println!(
        "{:12} {:>7} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8}",
        "file", "blocks", "min", "p10", "p25", "p50", "p90", "max", "under"
    );
    for file in files {
        let data = std::fs::read(&file).expect("the file reads");
        let mut yields: Vec<u32> = data
            .chunks(rar20::PARSE_BLOCK_BYTES)
            .map(rar20::sample_yield_per_mille)
            .collect();
        if yields.is_empty() {
            continue;
        }
        let under = yields.iter().filter(|&&y| !rar20::sample_worth(y)).count();
        yields.sort_unstable();
        let at = |q: usize| yields[(yields.len() - 1) * q / 100];
        let name = std::path::Path::new(&file)
            .file_name()
            .map_or(file.clone(), |n| n.to_string_lossy().into_owned());
        println!(
            "{:12} {:>7} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>7.1}%",
            name,
            yields.len(),
            yields[0],
            at(10),
            at(25),
            at(50),
            at(90),
            yields[yields.len() - 1],
            100.0 * under as f64 / yields.len() as f64
        );
    }
}
