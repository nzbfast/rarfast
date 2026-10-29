//! What the RAR 5 apply stage is handed, counted rather than timed.
//!
//! The 21 Sep 2026 finding is that at a real tape width the parallel
//! decode is APPLY bound, and the apply stage's cost is per OPERATION and
//! per output BYTE in proportions nothing in this repository has counted.
//! This lab prints those counts for each cached H2 corpus so a design can
//! be argued from the mix rather than from a guess: how many operations
//! the one apply thread walks, how many of them are literal runs, how long
//! a run is, and how many bytes each kind of operation moves.
//!
//! It reads the archives the gate bench caches under
//! `target/bench-h2`; run that bench once first. Nothing here is timed:
//! a count is a property of the stream and is the same on every box.

fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("run `cargo bench -p rarkit --bench two_arm` once to cache the corpora")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rar"))
        .collect();
    names.sort();
    println!(
        "{:<26} {:>12} {:>12} {:>10} {:>10} {:>9} {:>7} {:>10} {:>9}",
        "corpus", "bytes", "ops", "lit runs", "matches", "repeats", "filt", "bytes/op", "run len"
    );
    for name in names {
        let archive = std::fs::read(dir.join(&name)).unwrap();
        let census = match rarkit::internals::rar5::census(&archive) {
            Ok(c) => c,
            Err(err) => {
                println!("{name:<26} skipped: {err}");
                continue;
            }
        };
        let runs = census
            .operations
            .saturating_sub(census.matches + census.repeats + census.filters);
        let per_op = census.bytes as f64 / census.operations.max(1) as f64;
        let run_len = census.literals as f64 / runs.max(1) as f64;
        println!(
            "{:<26} {:>12} {:>12} {:>10} {:>10} {:>9} {:>7} {:>10.1} {:>9.1}",
            name.trim_end_matches(".rar"),
            census.bytes,
            census.operations,
            runs,
            census.matches,
            census.repeats,
            census.filters,
            per_op,
            run_len
        );
        if let Ok(shape) = rarkit::internals::rar5::apply_shape(&archive) {
            // WHICH ARM each operation takes, which the counts above do
            // not say and a lever aimed at one arm has to know.
            for (bucket, count) in rarkit::internals::rar5::APPLY_SHAPE_NAMES
                .iter()
                .zip(shape.iter())
            {
                println!("{:<26} {:>12} {bucket}", "", count);
            }
        }
        // WHAT WOULD NOT HAVE TO BE ON THE APPLY THREAD AT ALL, which
        // the two counts above do not ask. A lane holding the first N
        // bytes of its own block can resolve a match whose source lies
        // inside them into its own staging buffer, leaving the apply
        // thread a staged RUN between the matches that reach further
        // back. The last two lines are the arithmetic that decides
        // whether that is worth building.
        #[cfg(feature = "h2-locality-census")]
        if let Ok(loc) = rarkit::internals::rar5::locality(&archive) {
            for (bucket, count) in rarkit::internals::rar5::LOCALITY_NAMES
                .iter()
                .zip(loc.iter())
            {
                println!("{:<26} {:>12} {bucket}", "", count);
            }
            let today = loc[0].max(1);
            let residual = loc[14] + loc[15];
            println!(
                "{:<26} {:>12} RESIDUAL apply ops, {:.1}% of today's {} ({:.2}x fewer)",
                "",
                residual,
                100.0 * residual as f64 / today as f64,
                loc[0],
                today as f64 / residual.max(1) as f64
            );
            // THE CEILING, which is what closes or opens the direction:
            // holes wished away, a lane holding every byte its block has
            // produced. An unresolved operation still needs a run beside
            // it, and a run is an operation, so removing match operations
            // ADDS run operations, and the ceiling can sit ABOVE today.
            let ceiling = loc[20] + loc[21];
            println!(
                "{:<26} {:>12} CEILING apply ops with holes wished away, {:.1}% of today's ({} runs + {} ops)",
                "",
                ceiling,
                100.0 * ceiling as f64 / today as f64,
                loc[20],
                loc[21]
            );
            let run_len = loc[16] as f64 / loc[14].max(1) as f64;
            println!(
                "{:<26} {:>12.1} bytes an apply operation after resolution, run len {:.1}",
                "",
                loc[16] as f64 / residual.max(1) as f64,
                run_len
            );
        }
        if let Ok((blocks, groups, scanned)) = rarkit::internals::rar5::plan_shape(&archive) {
            println!(
                "{:<26} {:>12} blocks {:>10} groups {:>12} group-slots scanned by the release pass",
                "", blocks, groups, scanned
            );
        }
    }
}
