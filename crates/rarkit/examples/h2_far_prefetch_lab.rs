//! THE FAR-COPY PREFETCH, PRICED ONE BINARY AGAINST ITSELF, untimed.
//!
//! The RAR 5 text rows fail on one apply thread, and on `text_64m_m3`
//! that thread's time is the match copy, whose source sits up to a whole
//! dictionary behind the write point (the 22 Sep
//! per-operation table). One prefetch hint is allowed for it. This
//! lab says, before any timed hold, what the hint can buy and what it
//! does buy:
//!
//! - the CEILING: `probe::apply_arms::NEAR_SOURCE` copies every match from
//!   a hot byte instead. WRONG BYTES by design, a subtraction bound: a
//!   perfect prefetch could hide the far miss and nothing more, and this
//!   arm has no miss to hide;
//! - the LEVER: `probe::set_far_prefetch` at several depths, BYTE EXACT,
//!   each depth's output compared with the shipped walk's before any
//!   figure is printed.
//!
//! `--cells=` names the cells between the two controls, comma separated,
//! each `DEPTH[:MODE]` (MODE `all`, `dry` or `ungated`) or `ceiling`:
//! `--cells=ceiling,48,64,128,64:dry` prices a depth ladder beside its DRY
//! subtraction (the far-miss depth ladder,
//! whose second-hint, burst, gate-sample and wrapped-copy dials were
//! measured, DECLINED and not kept). Without it the cells are the
//! ones the far-copy prefetch work priced.
//!
//! Beside the medians, `pair` is the median over pairs of control A over
//! the cell WITHIN one pair, which a box drifting between pairs cannot
//! move the way it moves two medians taken minutes apart.
//!
//! The shipped walk rides at BOTH ENDS of every rotation as the null
//! control, and the table is refused if the
//! two disagree past the tolerance. Nothing here is a gate figure and no
//! old engine is linked in: every number is a ratio between cells of one
//! process. The apply stage's own busy time (`probe::pipeline_split`) is
//! the denominator beside the member's wall. CPU seconds come from the
//! timed hold's `two_arm` columns, not from here.
//!
//! Reads the archives the gate bench caches under `target/bench-h2`.

#[cfg(feature = "h2-apply-arms")]
use std::time::Instant;

#[cfg(feature = "h2-apply-arms")]
use rarkit::probe::apply_arms as arms;
#[cfg(feature = "h2-apply-arms")]
use rarkit::probe::far_prefetch_modes as modes;

#[cfg(not(feature = "h2-apply-arms"))]
fn main() {
    eprintln!(
        "REFUSING: this lab needs the apply walk's bound arm.\n\
         Build it with --features bench-internals,test-support,h2-apply-arms."
    );
    std::process::exit(2);
}

#[cfg(feature = "h2-apply-arms")]
fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    v[v.len() / 2]
}

/// Median absolute deviation as a percentage of the median, never the
/// range.
#[cfg(feature = "h2-apply-arms")]
fn mad_percent(xs: &[f64]) -> f64 {
    let m = median(xs);
    let devs: Vec<f64> = xs.iter().map(|x| (x - m).abs()).collect();
    100.0 * median(&devs) / m
}

#[cfg(feature = "h2-apply-arms")]
#[derive(Default)]
struct Cell {
    wall: Vec<f64>,
    busy: Vec<f64>,
}

/// One cell: a bound arm, or the shipped arm at a prefetch depth and a
/// pass mode (`probe::far_prefetch_modes`).
#[cfg(feature = "h2-apply-arms")]
#[derive(Clone)]
struct Arm {
    arm: u8,
    depth: usize,
    mode: u8,
    what: String,
}

#[cfg(feature = "h2-apply-arms")]
fn cell(arm: u8, depth: usize, mode: u8, what: &str) -> Arm {
    Arm {
        arm,
        depth,
        mode,
        what: what.to_string(),
    }
}

/// One `--cells=` token: `ceiling`, `wrapstride`, or `DEPTH[:MODE]`
/// (`wrapstride:DEPTH` for the wrap stride arm at a prefetch depth).
#[cfg(feature = "h2-apply-arms")]
fn parse_cell(token: &str) -> Option<Arm> {
    if let Some(rest) = token.strip_prefix("wrapstride") {
        let depth = match rest.strip_prefix(':') {
            Some(d) => d.parse().ok()?,
            None if rest.is_empty() => 0,
            None => return None,
        };
        return Some(cell(
            arms::WRAP_STRIDE,
            depth,
            modes::ALL,
            &format!("WRAP STRIDE (byte exact), depth {depth}"),
        ));
    }
    if token == "ceiling" {
        return Some(cell(
            arms::NEAR_SOURCE,
            0,
            modes::ALL,
            "CEILING: near source (wrong bytes)",
        ));
    }
    let (spec, mode) = token.split_once(':').unwrap_or((token, "all"));
    let depth = spec.parse().ok()?;
    let (mode, said) = match mode {
        "all" => (modes::ALL, "gated"),
        "dry" => (modes::DRY, "DRY ungated"),
        "ungated" => (modes::UNGATED, "UNGATED"),
        _ => return None,
    };
    Some(Arm {
        arm: arms::SHIPPED,
        depth,
        mode,
        what: format!("depth {depth}, {said}"),
    })
}

#[cfg(feature = "h2-apply-arms")]
fn run_once(archive: &[u8], arm: &Arm, width: usize) -> (f64, f64, Vec<u8>) {
    rarkit::probe::set_apply_arm(arm.arm);
    rarkit::probe::set_far_prefetch(Some(arm.depth));
    rarkit::probe::set_far_prefetch_mode(arm.mode);
    rarkit::probe::reset_pipeline_split();
    let from = Instant::now();
    let out = rarkit::internals::rar5::extract_scheduled(archive, width, None, true)
        .expect("rarkit extracts under every arm");
    let wall = from.elapsed().as_secs_f64();
    let (_, _, busy_ns, _, _, _) = rarkit::probe::pipeline_split();
    rarkit::probe::set_apply_arm(arms::SHIPPED);
    rarkit::probe::set_far_prefetch(None);
    rarkit::probe::set_far_prefetch_mode(modes::ALL);
    let bytes = out.into_iter().flat_map(|(_, b)| b).collect();
    (wall, busy_ns as f64 * 1e-9, bytes)
}

#[cfg(feature = "h2-apply-arms")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str, default: usize| -> usize {
        args.iter()
            .find_map(|a| a.strip_prefix(name).and_then(|n| n.parse().ok()))
            .unwrap_or(default)
    };
    let width = flag("--width=", 8);
    let pairs = flag("--pairs=", 15);
    let tolerance = 0.015;
    // `--dir=bench-f` reads the f/ rows' cached archives instead.
    let sub = args
        .iter()
        .find_map(|a| a.strip_prefix("--dir="))
        .unwrap_or("bench-h2");
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(sub);
    let census_only = args.iter().any(|a| a == "--census");

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

    let middle: Vec<Arm> = match args.iter().find_map(|a| a.strip_prefix("--cells=")) {
        Some(list) => {
            let mut cells = Vec::new();
            for token in list.split(',').filter(|t| !t.is_empty()) {
                match parse_cell(token) {
                    Some(arm) => cells.push(arm),
                    None => {
                        println!(
                            "REFUSING: --cells token {token:?} is not DEPTH[:MODE], wrapstride[:DEPTH] or ceiling."
                        );
                        std::process::exit(2);
                    }
                }
            }
            cells
        }
        None => vec![
            cell(
                arms::NEAR_SOURCE,
                0,
                modes::ALL,
                "CEILING: near source (wrong bytes)",
            ),
            cell(arms::SHIPPED, 16, modes::ALL, "chunks of 16, gated"),
            cell(arms::SHIPPED, 32, modes::ALL, "chunks of 32, gated"),
            cell(arms::SHIPPED, 64, modes::ALL, "chunks of 64, gated"),
            cell(arms::SHIPPED, 64, modes::UNGATED, "chunks of 64, UNGATED"),
            cell(arms::SHIPPED, 64, modes::DRY, "chunks of 64, DRY ungated"),
        ],
    };
    if middle.is_empty() {
        println!("REFUSING: --cells named no cell.");
        std::process::exit(2);
    }
    let mut all = vec![cell(
        arms::SHIPPED,
        0,
        modes::ALL,
        "shipped, no hint (control A)",
    )];
    all.extend(middle);
    all.push(cell(
        arms::SHIPPED,
        0,
        modes::ALL,
        "shipped, no hint (control B)",
    ));
    let control_a = 0usize;
    let control_b = all.len() - 1;

    for name in names {
        let archive = std::fs::read(dir.join(&name)).expect("the cached archive reads");
        let label = name.trim_end_matches(".rar").to_string();
        println!("\n=== {label} ===");
        // THE COUNT the gate's bytes-per-operation test reads, over the
        // whole member rather than a tape's first 256 operations.
        if census_only {
            match rarkit::internals::rar5::census(&archive) {
                Ok(c) => {
                    let blocks = rarkit::internals::rar5::plan_shape(&archive)
                        .map_or(0, |(blocks, _, _)| blocks);
                    println!(
                        "  census: {} ops, {} bytes, {:.1} bytes an op, {} matches, {} tapes, {:.0} ops a tape",
                        c.operations,
                        c.bytes,
                        c.bytes as f64 / c.operations.max(1) as f64,
                        c.matches,
                        blocks,
                        c.operations as f64 / blocks.max(1) as f64
                    )
                }
                Err(err) => println!("  census refused: {err}"),
            }
            // WHICH PATH EACH COPY TAKES, shipped and under the ceiling
            // arm's distance cap: the ceiling's gain includes every copy it
            // moves off the slow path, which no hint can.
            // Needs `--features copy-census` as well.
            #[cfg(feature = "copy-census")]
            for (said, reach) in [
                ("shipped", usize::MAX),
                ("ceiling", rarkit::probe::apply_arms::NEAR_SOURCE_REACH),
            ] {
                match rarkit::internals::rar5::copy_path_census(&archive, reach) {
                    Ok(c) => {
                        let copies: u64 = c[..5].iter().sum();
                        let pct = |n: u64| 100.0 * n as f64 / copies.max(1) as f64;
                        println!(
                            "  copies, {said}: {copies}, fast {:.1}%, slow for length {:.1}%, near {:.1}%, WRAPPED {:.1}%, ring end {:.1}%, {} bytes slow",
                            pct(c[0]),
                            pct(c[1]),
                            pct(c[2]),
                            pct(c[3]),
                            pct(c[4]),
                            c[5]
                        );
                        println!(
                            "  copies, {said}, MIRROR layout: slow {} ({:.1}%), {} bytes slow, {} laps, {} bytes mirrored; EDGE form: wrapped left slow {} ({:.3}%)",
                            c[6],
                            pct(c[6]),
                            c[7],
                            c[9],
                            c[9] * 64,
                            c[8],
                            pct(c[8])
                        );
                    }
                    Err(err) => println!("  copy census refused: {err}"),
                }
            }
            continue;
        }

        // ONE CELL A PROCESS, for a counter outside the process (`perf
        // stat` on Linux): `--cell=N` runs `all[N]` `pairs` times and
        // nothing else, so the difference between two processes at
        // different `--pairs` is that cell's cost a round with the
        // archive read, the process start and the first run's page faults
        // subtracted out. No null control and no byte check here: the
        // table mode above carries both, and this mode is read beside it.
        if let Some(index) = args.iter().find_map(|a| {
            a.strip_prefix("--cell=")
                .and_then(|n| n.parse::<usize>().ok())
        }) {
            let arm = &all[index.min(all.len() - 1)];
            let mut busy = Vec::new();
            let mut wall = Vec::new();
            for _ in 0..pairs {
                let (w, b, _) = run_once(&archive, arm, width);
                wall.push(w);
                busy.push(b);
            }
            println!(
                "  cell {index} ({}): {pairs} runs, busy {:.3} ms, wall {:.3} ms (medians)",
                arm.what,
                median(&busy) * 1e3,
                median(&wall) * 1e3
            );
            continue;
        }

        // BYTE EXACT FIRST: every hinted depth against the shipped walk,
        // before any figure. The bound arm is excluded, being wrong bytes
        // by design.
        let (_, _, shipped) = run_once(&archive, &all[control_a], width);
        for arm in all
            .iter()
            .filter(|a| (a.arm == arms::SHIPPED && a.depth != 0) || a.arm == arms::WRAP_STRIDE)
        {
            let (_, _, bytes) = run_once(&archive, arm, width);
            if bytes != shipped {
                println!(
                    "REFUSING: {} changed the output. Nothing measured.",
                    arm.what
                );
                std::process::exit(3);
            }
        }
        println!(
            "  byte exact: every prefetch depth and the wrap stride arm match the shipped walk ({} bytes)",
            shipped.len()
        );

        let mut cells: Vec<Cell> = (0..all.len()).map(|_| Cell::default()).collect();
        for pair in 0..pairs {
            // Rotate the order each pair so no arm owns a position.
            for step in 0..all.len() {
                let index = if step == 0 || step == all.len() - 1 {
                    step
                } else {
                    1 + (step - 1 + pair) % (all.len() - 2)
                };
                let (wall, busy, _) = run_once(&archive, &all[index], width);
                cells[index].wall.push(wall);
                cells[index].busy.push(busy);
            }
        }
        let null = median(&cells[control_b].busy) / median(&cells[control_a].busy);
        println!("  NULL CONTROL (shipped at both ends): {null:.4}x");
        if (null - 1.0).abs() > tolerance {
            println!(
                "  REFUSING the table: the null control moved past {:.1} percent.",
                tolerance * 100.0
            );
            continue;
        }
        let mut base_busy = cells[control_a].busy.clone();
        base_busy.extend_from_slice(&cells[control_b].busy);
        let mut base_wall = cells[control_a].wall.clone();
        base_wall.extend_from_slice(&cells[control_b].wall);
        let (bb, bw) = (median(&base_busy), median(&base_wall));
        println!(
            "  {:<38} {:>9} {:>9} {:>12} {:>12} {:>10} {:>7}",
            "cell", "busy ms", "wall ms", "busy base/it", "wall base/it", "busy pair", "MAD%"
        );
        for (index, arm) in all.iter().enumerate() {
            let busy = median(&cells[index].busy);
            let wall = median(&cells[index].wall);
            // Control A over this cell inside each pair, then the median.
            let paired: Vec<f64> = cells[control_a]
                .busy
                .iter()
                .zip(&cells[index].busy)
                .map(|(a, c)| a / c)
                .collect();
            println!(
                "  {:<38} {:>9.3} {:>9.3} {:>11.4}x {:>11.4}x {:>9.4}x {:>7.2}",
                arm.what,
                busy * 1e3,
                wall * 1e3,
                bb / busy,
                bw / wall,
                median(&paired),
                mad_percent(&cells[index].wall)
            );
        }
    }
}
