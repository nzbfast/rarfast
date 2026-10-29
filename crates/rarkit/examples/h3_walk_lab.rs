//! Spec H3 lab: the tree match finder's WALK alone, at a range of walker
//! counts, so its scaling can be attributed rather than guessed at.
//!
//! `h3_walk_lab <input> [dictionary bytes] [walkers,...]`

#[cfg(feature = "parallel")]
fn main() {
    use rarkit::internals::rar20::{on_threads, walk_probe};
    let args: Vec<String> = std::env::args().skip(1).collect();
    let input = args.first().expect("an input file");
    let dictionary: usize = args.get(1).map_or(4 << 20, |x| x.parse().unwrap());
    let counts: Vec<usize> = args.get(2).map_or_else(
        || vec![1, 2, 4, 8, 12, 16],
        |x| x.split(',').map(|n| n.parse().unwrap()).collect(),
    );
    // Bins per walker, alternated in the same minutes: 1 is the deal this
    // engine had (one bin per walker, `bucket % walkers`, no offer), and
    // anything above it is the offered deal. Both arms run in this one
    // process, so the load is the same load for each.
    let arms: Vec<usize> = args.get(3).map_or_else(
        || vec![1, 8],
        |x| x.split(',').map(|n| n.parse().unwrap()).collect(),
    );
    let rounds: usize = args.get(4).map_or(5, |x| x.parse().unwrap());
    let data = std::fs::read(input).expect("the input reads");
    println!(
        "{} bytes, dictionary {dictionary}, {rounds} rounds",
        data.len()
    );
    println!("walkers  bins/walker   wall s  ns/byte   busy s   width  busiest/mean walker");
    for walkers in counts {
        // Alternated round by round, not arm by arm: a shared box's load
        // moves inside a minute, and alternating is what stops it landing
        // on one arm.
        let mut runs: Vec<Vec<(f64, f64, f64)>> = vec![Vec::new(); arms.len()];
        let mut positions = 0;
        let mut hot = 0;
        let mut balanced = 0;
        for _ in 0..rounds {
            for (arm, &bins) in arms.iter().enumerate() {
                let probe = on_threads(walkers, || walk_probe(&data, dictionary, walkers, 4, bins));
                runs[arm].push((
                    probe.wall,
                    probe.busy,
                    probe.chunk_max / probe.chunk_mean.max(1e-12),
                ));
                positions = probe.positions;
                hot = probe.bucket_max;
                balanced = probe.lpt;
            }
        }
        println!(
            "         positions {positions}, busiest bucket {hot} ({:.1}%, the floor), \
a balanced deal {:.2}x the mean walker",
            100.0 * hot as f64 / positions as f64,
            balanced as f64 * walkers as f64 / positions as f64,
        );
        for (arm, &bins) in arms.iter().enumerate() {
            runs[arm].sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            let (wall, busy, spread) = runs[arm][rounds / 2];
            println!(
                "{walkers:>7}  {bins:>11}  {wall:>7.4}  {:>7.1}  {busy:>7.3}  {:>6.2}  {spread:>10.3}",
                wall * 1e9 / data.len() as f64,
                busy / wall,
            );
        }
    }
}

#[cfg(not(feature = "parallel"))]
fn main() {
    println!("the walk lab needs the `parallel` feature");
}
