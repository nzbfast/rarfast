//! The symbol census of RAR 5 archives named on the command line, for the
//! per-symbol accounting of the decode symbol race (29
//! Sep 2026): how many literals, matches, repeats and filter records each
//! archive's LZ members decode to, so a whole-process instruction count
//! can be split per literal and per match by subtraction across archives.
//!
//! Untimed and not a gate leg. Implemented from
//! `specs/SPEC-H2-rarkit-rar5-lz.md` and this crate's own seam alone.

fn main() {
    println!(
        "{:<28} {:>14} {:>12} {:>12} {:>10} {:>9} {:>7}",
        "archive", "bytes", "literals", "matches", "repeats", "filters", "ops"
    );
    for path in std::env::args().skip(1) {
        let archive = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                println!("{path}: {err}");
                continue;
            }
        };
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or(path.clone());
        match rarkit::internals::rar5::census(&archive) {
            Ok(c) => println!(
                "{:<28} {:>14} {:>12} {:>12} {:>10} {:>9} {:>7}",
                name, c.bytes, c.literals, c.matches, c.repeats, c.filters, c.operations
            ),
            Err(err) => println!("{name:<28} failed: {err}"),
        }
        // The single-gap table shape: blocks and symbol bits under it.
        match rarkit::internals::rar5::gap_shape_census(&archive) {
            Ok(g) => println!(
                "{:<28} gap shape: {} of {} blocks ({:.1}%), {} of {} symbol bits ({:.1}%)",
                name,
                g.gap_blocks,
                g.blocks,
                100.0 * g.gap_blocks as f64 / g.blocks.max(1) as f64,
                g.gap_bits,
                g.bits,
                100.0 * g.gap_bits as f64 / g.bits.max(1) as f64
            ),
            Err(err) => println!("{name:<28} gap census failed: {err}"),
        }
        // With `RARKIT_MATCH_SHAPE` set: the matches by length and
        // distance, count and bytes, for a writer's ratio counts.
        if std::env::var_os("RARKIT_MATCH_SHAPE").is_some() {
            match rarkit::internals::rar5::match_shape_census(&archive) {
                Ok(shape) => print_match_shape(&name, &shape),
                Err(err) => println!("{name:<28} match shape failed: {err}"),
            }
        }
    }
}

/// One line per length class: the fresh matches of each distance class as
/// count/bytes, then the repeats of that length.
fn print_match_shape(name: &str, shape: &rarkit::internals::rar5::MatchShapeCensus) {
    const LENGTHS: [&str; 10] = ["2", "3", "4", "5", "6", "7", "8", "9-16", "17-32", "33+"];
    const DISTANCES: [&str; 7] = [
        "<=256", "<=4K", "<=64K", "<=256K", "<=2M", "<=32M", "beyond",
    ];
    println!("{name} match shape, fresh matches as count/bytes by distance, then repeats:");
    print!("{:>6}", "length");
    for distance in DISTANCES {
        print!(" {distance:>22}");
    }
    println!(" {:>22}", "repeats");
    for (label, (row, repeats)) in LENGTHS.iter().zip(shape.fresh.iter().zip(shape.repeats)) {
        print!("{label:>6}");
        for (count, bytes) in row {
            print!(" {:>22}", format!("{count}/{bytes}"));
        }
        println!(" {:>22}", format!("{}/{}", repeats.0, repeats.1));
    }
    println!("{name} repeats of the last length: {}", shape.repeat_last);
}
