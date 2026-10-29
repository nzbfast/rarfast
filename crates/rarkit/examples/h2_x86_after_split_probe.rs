//! What is LEFT of the RAR 5 x86 address pass after the split, and whether a
//! second lever is in it.
//!
//! The question was whether collect-then-apply should be PROMOTED to the
//! shipped body.
//! It already is: the filter-drain work landed the same mechanism as a fixed
//! window split, in a better shape than first proposed (a stack window,
//! so no cap, no fallback and no allocation, and portable SWAR rather than
//! NEON). So the question this lab asks is the one after that: the pass is
//! still about 8 percent of `rar5_code_32m_m3_serial` and the leg needs about
//! 5 to reach the gate, so is there a second lever inside the split.
//!
//! Every arm keeps the split's two phases and changes ONE thing, so the table
//! subtracts rather than compares designs.
//!
//! The discipline, which the arms are worthless without:
//!
//! - Arms are INTERLEAVED round robin, never run one after the other. The
//!   x86-pass work recorded an apparent 13 percent difference between two
//!   instantiations that did not reproduce and INVERTED between runs,
//!   taken by a micro that ran each variant once in sequence; interleaving is
//!   what fixed it.
//! - A NULL CONTROL, the shipped arm against itself, runs FIRST and LAST. If
//!   either reads further from 1.0 than `--null-tolerance`, the lab prints no
//!   table at all. An untimed box moves, and a run that cannot see itself
//!   move has no business publishing a ratio.
//! - MEDIAN and MAD, never the minimum and never the range. Range widens with
//!   the sample count on its own.
//! - Every arm is held byte for byte against the shipped pass before anything
//!   is timed, in both record types.

use std::time::Instant;

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a wall clock"));
    let half = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[half - 1] + values[half]) / 2.0
    } else {
        values[half]
    }
}

/// Median absolute deviation as a percentage of the median.
fn mad_percent(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    let centre = median(&mut sorted);
    let mut spread: Vec<f64> = values.iter().map(|v| (v - centre).abs()).collect();
    let mad = median(&mut spread);
    if centre == 0.0 {
        0.0
    } else {
        mad / centre * 100.0
    }
}

fn flag(name: &str, default: f64) -> f64 {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            if let Some(value) = args.next().and_then(|v| v.parse().ok()) {
                return value;
            }
        }
    }
    default
}

fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    let data = std::fs::read(dir.join("code.dat"))
        .expect("run `cargo bench -p rarkit --bench two_arm rar5_code_32m_m3` once first");
    let span = flag("--span", 65_536.0) as usize;
    let pairs = flag("--pairs", 15.0) as usize;
    let tolerance = flag("--null-tolerance", 1.0);

    // Arm 0 is the shipped split body and every other arm is held to it.
    // `internals::rar5::rar5_x86_pass`'s arm numbering is the seam's.
    let arms: &[(u8, &str)] = &[
        (1, "shipped split, BATCH 256"),
        (2, "split, BATCH 64"),
        (3, "split, BATCH 1024"),
        (4, "split, two words a step"),
        #[cfg(target_arch = "aarch64")]
        (5, "split, NEON sixteen bytes a compare"),
        // The arm aimed at the mechanism that actually paid. The two
        // above it are WIDTH arms, and the filter-drain work predicts
        // width will do nothing here, because its pass was dependence
        // bound rather than issue bound: its fused attempt was 2x SLOWER
        // than walking and the fixed stride alone only 1.25x. That
        // prediction is recorded before this runs so the table can
        // embarrass it rather than be fitted to it.
        (6, "split, five byte skip moved to phase two"),
        (0, "walking, the pre-21-Sep body"),
    ];

    println!(
        "code.dat {} bytes, span {span}, {pairs} pairs a cell, \
         null tolerance {tolerance} percent",
        data.len()
    );

    let run = |arm: u8, jump: bool, work: &mut [u8]| {
        for (index, chunk) in work.chunks_mut(span).enumerate() {
            rarkit::internals::rar5::rar5_x86_pass(chunk, (index * span) as u32, jump, arm);
        }
    };

    for &jump in &[false, true] {
        let kind = if jump {
            "type 2, calls and jumps"
        } else {
            "type 1, calls alone"
        };

        // Correctness before any timing, in this record type.
        let mut want = data.clone();
        run(1, jump, &mut want);
        assert_ne!(want, data, "the shipped pass changed nothing: {kind}");
        for &(arm, name) in arms {
            let mut got = data.clone();
            run(arm, jump, &mut got);
            assert_eq!(
                want, got,
                "arm {arm} ({name}) disagrees with the shipped split: {kind}"
            );
        }

        // A cell is one arm timed once over the whole corpus. Cells are
        // interleaved so a drift inside the run reaches every arm.
        let mut walls: Vec<Vec<f64>> = vec![Vec::new(); arms.len()];
        let mut null_first: Vec<f64> = Vec::new();
        let mut null_last: Vec<f64> = Vec::new();
        let time_one = |arm: u8| {
            let mut work = data.clone();
            let start = Instant::now();
            for (index, chunk) in work.chunks_mut(span).enumerate() {
                rarkit::internals::rar5::rar5_x86_pass(chunk, (index * span) as u32, jump, arm);
            }
            let took = start.elapsed().as_secs_f64();
            std::hint::black_box(&work);
            took
        };

        for _ in 0..pairs {
            null_first.push(time_one(1) / time_one(1).max(f64::MIN_POSITIVE));
        }
        for _ in 0..pairs {
            for (slot, &(arm, _)) in arms.iter().enumerate() {
                walls[slot].push(time_one(arm));
            }
        }
        for _ in 0..pairs {
            null_last.push(time_one(1) / time_one(1).max(f64::MIN_POSITIVE));
        }

        let first = median(&mut null_first.clone());
        let last = median(&mut null_last.clone());
        let worst = (first - 1.0).abs().max((last - 1.0).abs()) * 100.0;
        println!(
            "\n{kind}: null control {first:.4} first, {last:.4} last, \
             worst {worst:.2} percent"
        );
        if worst > tolerance {
            println!(
                "  REFUSED: the null control moved more than {tolerance} percent, \
                 so no row of this cell is a result."
            );
            continue;
        }

        let shipped = median(&mut walls[0].clone());
        println!("| arm | ms | ns a byte | shipped / it | MAD% |");
        println!("|---|---|---|---|---|");
        for (slot, &(_, name)) in arms.iter().enumerate() {
            let wall = median(&mut walls[slot].clone());
            println!(
                "| {name} | {:.3} | {:.3} | {:.4}x | {:.2} |",
                wall * 1e3,
                wall * 1e9 / data.len() as f64,
                shipped / wall,
                mad_percent(&walls[slot]),
            );
        }
    }
}
