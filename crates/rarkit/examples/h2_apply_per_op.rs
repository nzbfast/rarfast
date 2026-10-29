//! WHAT ONE OPERATION COSTS INSIDE `tape::apply`, by SUBTRACTION.
//!
//! The RAR 5 parallel rows fail on one apply thread bound by OPERATION
//! COUNT, and every STRUCTURAL direction
//! off that thread as measured closed: in-lane match resolution by its
//! own ceiling, the deeper hand-off, the ring floor, the in-place write,
//! the literal-run fold, the stride ladder. What is left is the cost of
//! one operation, and the record's own lesson about how to price it is
//! blunt: self time over a dependency-bound loop does not name the
//! marginal instruction, and attribution is
//! not subtraction. Two earlier changes took a profile's top
//! line as a lever and both regressed.
//!
//! So this removes a thing and remeasures. Each arm of `probe::apply_arms`
//! deletes one per-operation cost from the walk; most produce WRONG BYTES
//! and are upper BOUNDS on any lever aimed at what they removed. A bound
//! at the instrument's own floor closes a direction with no lever written,
//! which is how the near-match path was priced and declined.
//!
//! Nothing here is a gate figure and no old engine is anywhere near it:
//! every number is a ratio between arms of ONE binary, which is what
//! survives the loaded untimed box this is meant to run on. The apply
//! stage's own busy nanoseconds (`probe::pipeline_split`) are the
//! denominator rather than the member's wall, because that is the stage
//! the arms change.
//!
//! Reads the archives the gate bench caches under `target/bench-h2`.

#![allow(clippy::needless_doctest_main)]

#[cfg(feature = "h2-apply-arms")]
use std::time::Instant;

#[cfg(feature = "h2-apply-arms")]
use rarkit::probe::apply_arms as arms;

/// Pairs a cell by default. Fifteen, the figure every A/B in
/// here uses; `--pairs=N` raises it where a box needs it.
#[cfg(feature = "h2-apply-arms")]
const PAIRS: usize = 15;
/// How far the two null controls may disagree before the table is
/// refused outright. The pairing's own floor was measured at 1.0002x,
/// 1.0005x and 1.0114x on an M3 Mac, so a tolerance under about a point
/// would refuse a sound hold on this box.
#[cfg(feature = "h2-apply-arms")]
const NULL_TOLERANCE: f64 = 0.015;
/// The width the failing rows run at, and the carried ceiling.
///
/// `--width=N` lowers it, and on a box carrying other work that is
/// worth doing: the per-operation cost of the apply walk does not
/// depend on how many lanes feed it, while the SCHEDULING noise of
/// eight lanes against a busy box does. A narrow run measures the same
/// question through a quieter instrument.
#[cfg(feature = "h2-apply-arms")]
const WIDTH: usize = 8;

/// Without the arms there is nothing to subtract, and a lab that ran
/// anyway would print a table of one arm against itself. It refuses.
#[cfg(not(feature = "h2-apply-arms"))]
fn main() {
    eprintln!(
        "REFUSING: this lab is the apply walk's ablation arms and nothing else.\n\
         Build it with --features bench-internals,h2-apply-arms.\n\
         The arms are behind a feature of their OWN so `two_arm` never\n\
         compiles them: on 22 Sep 2026 they cost a gate 24 percent of one\n\
         leg's wall by sitting behind `test-support`, which that bench\n\
         enables."
    );
    std::process::exit(2);
}

#[cfg(feature = "h2-apply-arms")]
fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    v[v.len() / 2]
}

/// Median absolute deviation as a percentage of the median. Never the
/// min-to-max range, which widens with the sample count on its own.
#[cfg(feature = "h2-apply-arms")]
fn mad_percent(xs: &[f64]) -> f64 {
    let m = median(xs);
    let devs: Vec<f64> = xs.iter().map(|x| (x - m).abs()).collect();
    if m == 0.0 {
        return f64::NAN;
    }
    100.0 * median(&devs) / m
}

/// One arm's samples: the member's wall and the apply stage's own busy
/// time, in seconds.
#[cfg(feature = "h2-apply-arms")]
#[derive(Default)]
struct Cell {
    wall: Vec<f64>,
    busy: Vec<f64>,
}

#[cfg(feature = "h2-apply-arms")]
fn run_once(archive: &[u8], arm: u8, width: usize) -> (f64, f64) {
    rarkit::probe::set_apply_arm(arm);
    rarkit::probe::reset_pipeline_split();
    let from = Instant::now();
    // An ablated arm writes wrong bytes on purpose, so the extraction's
    // OUTPUT is meaningless here and only its cost is read. It must still
    // succeed: every arm preserves the byte COUNT, so the member stops at
    // the operation it always stopped at.
    rarkit::internals::rar5::extract_scheduled(archive, width, None, true)
        .expect("rarkit extracts under every arm");
    let wall = from.elapsed().as_secs_f64();
    let (_, _, busy_ns, _, _, _) = rarkit::probe::pipeline_split();
    rarkit::probe::set_apply_arm(arms::SHIPPED);
    (wall, busy_ns as f64 * 1e-9)
}

#[cfg(feature = "h2-apply-arms")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let width: usize = args
        .iter()
        .find_map(|a| a.strip_prefix("--width=").and_then(|n| n.parse().ok()))
        .unwrap_or(WIDTH);
    let pairs: usize = args
        .iter()
        .find_map(|a| a.strip_prefix("--pairs=").and_then(|n| n.parse().ok()))
        .unwrap_or(PAIRS);
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");

    // A STEADY TARGET FOR AN EXTERNAL SAMPLER, rarkit's own process and
    // no other: the old engine is never sampled here, and it is
    // not linked into this example at all.
    if let Some(soak) = args
        .iter()
        .find_map(|a| a.strip_prefix("--soak=").map(str::to_owned))
    {
        let archive = std::fs::read(dir.join(format!("{soak}.rar"))).expect("the archive reads");
        let seconds: u64 = args
            .iter()
            .find_map(|a| a.strip_prefix("--seconds=").and_then(|n| n.parse().ok()))
            .unwrap_or(30);
        let until = Instant::now() + std::time::Duration::from_secs(seconds);
        let mut rounds = 0u64;
        while Instant::now() < until {
            rarkit::internals::rar5::extract_scheduled(&archive, width, None, true)
                .expect("rarkit extracts");
            rounds += 1;
        }
        println!("soak {soak}: {rounds} rounds in {seconds} s at width {width}");
        return;
    }

    let wanted: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("run `cargo bench -p rarkit --bench two_arm` once to cache the corpora")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rar"))
        .filter(|n| wanted.is_empty() || wanted.iter().any(|o| n.contains(o.as_str())))
        .collect();
    names.sort();
    if names.is_empty() {
        println!("REFUSING: no cached corpus matched. Nothing measured.");
        std::process::exit(2);
    }

    println!(
        "host parallelism {}, width {width}, {pairs} pairs a cell",
        std::thread::available_parallelism().map_or(0, |p| p.get())
    );

    for name in names {
        let archive = std::fs::read(dir.join(&name)).expect("the cached archive reads");
        let label = name.trim_end_matches(".rar").to_string();
        println!("\n=== {label} ===");

        // THE COUNTS, which are what turn a saving into nanoseconds per
        // operation. A share without a count beside it is not evidence.
        let census = match rarkit::internals::rar5::census(&archive) {
            Ok(c) => c,
            Err(err) => {
                println!("  skipped: {err}");
                continue;
            }
        };
        let runs = census
            .operations
            .saturating_sub(census.matches + census.repeats + census.filters);
        let shape = rarkit::internals::rar5::apply_shape(&archive).ok();
        println!(
            "  ops {} = {} literal runs + {} matches + {} repeats + {} filters, {} bytes",
            census.operations, runs, census.matches, census.repeats, census.filters, census.bytes
        );
        if let Some(shape) = shape.as_ref() {
            println!(
                "  match arms: {} stride ladder, {} too NEAR, {} too LONG",
                shape[7], shape[8], shape[9]
            );
        }

        // THE NULL CONTROL, AND IT RIDES INSIDE THE ROTATION.
        //
        // The first version of this lab ran the control as a block of
        // pairs before the arms and another after them, and on a box
        // carrying twelve cores of other work it read 2.9, 3.3 and 6.2
        // percent and refused all three tables. A block at each end
        // measures the box's drift between the blocks, which is not what
        // the arms are exposed to: they are interleaved. The same
        // was learned on a second Mac:
        // a control cell BETWEEN cells is the only instrument.
        //
        // So the shipped arm appears TWICE in one rotation, at its two
        // ENDS, and the control is those two cells against each other.
        // It carries the same drift the arms carry and, sitting at the
        // ends, it measures the worst within-round position spread any
        // arm could suffer. Both shipped cells together are the base.
        let all = [
            (arms::SHIPPED, "shipped, every check and store (control A)"),
            (
                arms::NO_FRESH,
                "MatchState::fresh cut to one slot (wrong bytes)",
            ),
            (
                arms::NO_RANGE,
                "copy_match range check removed (byte exact)",
            ),
            (arms::NO_MATCH_COPY, "match copy removed (wrong bytes)"),
            (arms::NO_LIT_STORE, "literal store removed (wrong bytes)"),
            (
                arms::NO_STORES,
                "neither store: the WALK alone (wrong bytes)",
            ),
            (arms::SHIPPED, "shipped, every check and store (control B)"),
        ];
        let control_a = 0usize;
        let control_b = all.len() - 1;
        let mut cells: Vec<Cell> = (0..all.len()).map(|_| Cell::default()).collect();
        for _ in 0..pairs {
            for (index, (arm, _)) in all.iter().enumerate() {
                let (wall, busy) = run_once(&archive, *arm, width);
                cells[index].wall.push(wall);
                cells[index].busy.push(busy);
            }
        }

        let null = median(&cells[control_b].busy) / median(&cells[control_a].busy);
        println!(
            "  NULL CONTROL, the shipped arm at both ends of the rotation: {null:.4}x \
             (it must read 1.0000x; what it reads is this cell's FLOOR)"
        );
        let floor = (null - 1.0).abs();
        if floor > NULL_TOLERANCE {
            println!(
                "  REFUSING the table: the null control moved {:.2} percent, past the \
                 {:.2} percent tolerance. Nothing is attributed.",
                floor * 100.0,
                NULL_TOLERANCE * 100.0
            );
            continue;
        }

        let mut base_samples = cells[control_a].busy.clone();
        base_samples.extend_from_slice(&cells[control_b].busy);
        let base_busy = median(&base_samples);
        let mut base_walls = cells[control_a].wall.clone();
        base_walls.extend_from_slice(&cells[control_b].wall);
        let base_wall = median(&base_walls);
        println!(
            "  {:<44} {:>10} {:>10} {:>9} {:>8} {:>11}",
            "arm", "busy ms", "wall ms", "shipped/it", "MAD%", "ns/op saved"
        );
        for (index, (_, what)) in all.iter().enumerate() {
            let busy = median(&cells[index].busy);
            let wall = median(&cells[index].wall);
            let saved_ns = (base_busy - busy) * 1e9 / census.operations.max(1) as f64;
            println!(
                "  {:<44} {:>10.3} {:>10.3} {:>9.4}x {:>8.2} {:>11.3}",
                what,
                busy * 1e3,
                wall * 1e3,
                base_busy / busy,
                mad_percent(&cells[index].busy),
                saved_ns
            );
        }

        // THE ATTRIBUTION, each saving divided by the operations that
        // REACH the thing removed rather than by every operation. The
        // floor beside it is the null control's, and a figure inside the
        // floor is not a finding in either direction.
        // Indexed BY ARM and never by position: an arm added to the
        // rotation must not be able to silently re-point an attribution
        // line at its neighbour.
        let at = |arm: u8| -> usize {
            all.iter()
                .position(|(a, _)| *a == arm)
                .expect("every attributed arm is in the rotation")
        };
        // Every operation that reaches the match copy: a fresh match or
        // a repeat, both of which call it.
        let copies = census.matches + census.repeats;
        let per = |arm: u8, count: u64| -> f64 {
            (base_busy - median(&cells[at(arm)].busy)) * 1e9 / count.max(1) as f64
        };
        println!(
            "  PER OPERATION THAT REACHES IT, ns: fresh {:.3} over {} fresh matches; \
             admission test {:.3} over {} copies; whole match copy {:.3} over {} copies; \
             whole literal store {:.3} over {} runs",
            per(arms::NO_FRESH, census.matches),
            census.matches,
            per(arms::NO_RANGE, copies),
            copies,
            per(arms::NO_MATCH_COPY, copies),
            copies,
            per(arms::NO_LIT_STORE, runs),
            runs
        );
        let walk = median(&cells[at(arms::NO_STORES)].busy);
        println!(
            "  THE WALK ALONE costs {:.3} ns an operation ({:.1} percent of the apply \
             stage's {:.3} ms); the two stores are the other {:.1} percent",
            walk * 1e9 / census.operations.max(1) as f64,
            100.0 * walk / base_busy,
            base_busy * 1e3,
            100.0 * (base_busy - walk) / base_busy
        );
        println!(
            "  apply busy is {:.1} percent of the member's {:.3} ms wall at width {width}",
            100.0 * base_busy / base_wall,
            base_wall * 1e3
        );
        println!(
            "  THE FLOOR this cell's figures are read against: {:.3} ns an operation \
             ({:.2} percent of apply busy)",
            floor * base_busy * 1e9 / census.operations.max(1) as f64,
            floor * 100.0
        );
    }
}
