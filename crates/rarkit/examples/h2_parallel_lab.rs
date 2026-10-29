//! Where the RAR 5 parallel arm's WALL goes on one big member.
//!
//! An earlier reading says the parallel arm is apply bound, and says it from
//! a `sample` of one thread. A share of one thread's samples is not a
//! share of the member's wall, so this lab asks the same question in wall
//! terms and on the box the figures are wanted from:
//!
//! - a WIDTH LADDER, one lane to the ceiling, with the overlap on and
//!   off. A stage that saturates names the width it saturates at;
//! - the PIPELINE SPLIT out of `probe::pipeline_split`: how long the one
//!   apply stage waited for a tape, how long it spent applying one, how
//!   long the lanes spent decoding and how long they spent blocked
//!   handing a tape over. Apply bound and decode bound have opposite
//!   signatures here and the counters say which without a profiler;
//! - CPU seconds and threads-worth beside every wall, which is what
//!   says whether a lane was idle.
//!
//! Nothing here is a gate figure and nothing here is timed against the
//! old engine: it is rarkit against itself, so a loaded box moves every
//! row together. It reads the archives the gate bench caches under
//! `target/bench-h2`; run that bench once first.

use std::time::{Duration, Instant};

/// The widths to walk. The carried ceiling is 8 and `tape::workers` mins
/// the dial against it, so 12 and 16 are here to SHOW the ceiling rather
/// than to cross it: a flat pair of rows at the top is the evidence.
const WIDTHS: [usize; 8] = [1, 2, 3, 4, 6, 8, 12, 16];
/// Repeats per cell. The median is reported; a lab is not a gate and this
/// is enough to see a ladder's shape.
const REPS: usize = 5;

fn cpu_seconds() -> f64 {
    #[cfg(unix)]
    {
        // RUSAGE_SELF: every thread of this process, which is the point.
        // The known trap is peak RSS out of RUSAGE_CHILDREN;
        // this reads CPU out of SELF, which has no child in it at all.
        let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: getrusage fills the struct it is given; RUSAGE_SELF is
        // valid. The same call the gate bench makes, for the same
        // reason and with the same argument.
        #[allow(unsafe_code)]
        let ru = unsafe {
            libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr());
            ru.assume_init()
        };
        let user = ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 * 1e-6;
        let sys = ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 * 1e-6;
        user + sys
    }
    #[cfg(not(unix))]
    f64::NAN
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("no NaN wall"));
    xs[xs.len() / 2]
}

/// One cell: `reps` runs of `run`, answering the median wall and the mean
/// CPU seconds a run cost.
fn cell(reps: usize, mut run: impl FnMut()) -> (Duration, f64) {
    let mut walls = Vec::with_capacity(reps);
    let cpu_before = cpu_seconds();
    for _ in 0..reps {
        let from = Instant::now();
        run();
        walls.push(from.elapsed().as_secs_f64());
    }
    let cpu = (cpu_seconds() - cpu_before) / reps as f64;
    (Duration::from_secs_f64(median(walls)), cpu)
}

fn main() {
    let only: Vec<String> = std::env::args().skip(1).collect();
    // THE LADDER IS OPT-IN, and that default is deliberate. It is step
    // 1's instrument, its answer is recorded, and walking it again costs
    // minutes. A timed run must not depend on a flag
    // being parsed correctly to take the CHEAP path: the expensive one
    // is the one that has to be asked for.
    let ladder_wanted = only.iter().any(|a| a.as_str() == "--ladder");
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    // `--soak=<corpus>` runs ONE leg's parallel arm round and round at the
    // ceiling width, so an external sampler has a steady target. It is
    // rarkit's own process and no other: the old engine is timed here
    // and never sampled.
    if let Some(soak) = only
        .iter()
        .find_map(|a| a.strip_prefix("--soak=").map(str::to_owned))
    {
        let archive = std::fs::read(dir.join(format!("{soak}.rar"))).expect("the archive reads");
        let seconds: u64 = only
            .iter()
            .find_map(|a| a.strip_prefix("--seconds=").and_then(|n| n.parse().ok()))
            .unwrap_or(20);
        let until = Instant::now() + Duration::from_secs(seconds);
        let mut rounds = 0u64;
        while Instant::now() < until {
            rarkit::internals::rar5::extract_scheduled(&archive, 8, None, true)
                .expect("rarkit extracts");
            rounds += 1;
        }
        println!("soak {soak}: {rounds} rounds in {seconds} s at width 8");
        return;
    }
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("run `cargo bench -p rarkit --bench two_arm` once to cache the corpora")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rar"))
        .filter(|n| {
            let wanted: Vec<&String> = only.iter().filter(|o| !o.starts_with("--")).collect();
            wanted.is_empty() || wanted.iter().any(|o| n.contains(o.as_str()))
        })
        .collect();
    names.sort();

    println!(
        "host parallelism {}",
        std::thread::available_parallelism().map_or(0, |p| p.get())
    );

    for name in names {
        let archive = std::fs::read(dir.join(&name)).expect("the cached archive reads");
        let label = name.trim_end_matches(".rar").to_string();
        println!("\n=== {label} ===");

        // The SERIAL arm, which is the `_serial` leg's rarkit side and the
        // number every parallel row is worth comparing against: one thread
        // doing the decode and the apply fused, with no tape at all.
        let (serial, serial_cpu) = cell(REPS, || {
            rarkit::internals::rar5::extract(&archive, false).expect("rarkit extracts");
        });
        println!(
            "  serial (parallel off)   wall {:>9.2} ms   cpu {:>7.4} s   threads-worth {:>5.2}",
            serial.as_secs_f64() * 1e3,
            serial_cpu,
            serial_cpu / serial.as_secs_f64()
        );

        // The HUFFMAN SIDE ALONE, serially: `census` decodes every block
        // into a tape and counts it, applying nothing to a window. Against
        // the serial row above it splits the serial arm in two, and
        // against the ladder it says what there is to spread.
        let (decode, decode_cpu) = cell(REPS, || {
            rarkit::internals::rar5::census(&archive).expect("the census counts");
        });
        println!(
            "  tape decode alone, 1 thr wall {:>9.2} ms   cpu {:>7.4} s",
            decode.as_secs_f64() * 1e3,
            decode_cpu
        );

        // THE TWO LITERAL ARMS, in one binary against itself, which is
        // the only control that separates a change from its code layout,
        // and INTERLEAVED round by round, which is the only control that
        // separates it from a box moving under the run. The M3 Mac has
        // somebody working on it, so a lab run there reads a
        // moving box; alternating the arms puts the same drift under both
        // and the PAIRED figure survives it. Width 8 and the overlap on,
        // which is what ships.
        const PAIRS: usize = 15;
        let mut arms: [Vec<(f64, f64)>; 2] = [Vec::new(), Vec::new()];
        for _ in 0..PAIRS {
            for (slot, ladder) in [(0usize, true), (1usize, false)] {
                rarkit::probe::set_literal_ladder(Some(ladder));
                rarkit::probe::reset_pipeline_split();
                let from = Instant::now();
                rarkit::internals::rar5::extract_scheduled(&archive, 8, None, true)
                    .expect("rarkit extracts");
                let wall = from.elapsed().as_secs_f64();
                let (_, _, busy_ns, _, _, _) = rarkit::probe::pipeline_split();
                arms[slot].push((wall, busy_ns as f64 * 1e-9));
            }
        }
        rarkit::probe::set_literal_ladder(None);

        // THE SUBTRACTION, run before any lever is written: how much is
        // there to win at all on the near-match path. The ablated arm
        // takes the stride copy where the semantics forbid it, so it
        // costs what the best possible fast path would cost and produces
        // WRONG BYTES doing it. The difference is an upper BOUND on any
        // lever there, and a bound under about a point says do not write
        // one. Interleaved, same binary, for the usual reason.
        // A NULL CONTROL FOR THE PAIRING ITSELF, and it runs beside
        // every A/B rather than on request. Every A/B here runs arm 0
        // then arm 1 inside one pair, so anything that systematically
        // penalises the FIRST run of a pair - pages faulted into a fresh
        // 64 MiB sink, an allocator warming - would read as arm 1 being
        // faster, on every dial, and would flatter whatever change is
        // being measured. This runs the SAME arm in both slots. It must
        // read 1.0000x; what it actually reads is the bias every other
        // ratio in this lab carries.
        //
        // It costs one extra pair-set per corpus and it is worth that
        // in a timed run: it is the control that makes the ratios
        // beside it mean anything. Measured at 1.0002x and 1.0005x on
        // an M3 Mac, 21 Sep 2026.
        {
            let mut null: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
            for _ in 0..PAIRS {
                for slot in [0usize, 1usize] {
                    let from = Instant::now();
                    rarkit::internals::rar5::extract_scheduled(&archive, 8, None, true)
                        .expect("rarkit extracts");
                    null[slot].push(from.elapsed().as_secs_f64());
                }
            }
            let bias: Vec<f64> = null[1]
                .iter()
                .zip(null[0].iter())
                .map(|(b, a)| b / a)
                .collect();
            println!(
                "  NULL CONTROL, same arm in both slots: slot0 {:.2} ms, slot1 {:.2} ms, \
                 paired {:.4}x  (must be 1.0000x; anything else is ORDER BIAS)",
                median(null[0].clone()) * 1e3,
                median(null[1].clone()) * 1e3,
                median(bias)
            );
        }

        // INSIDE A HOLD ONLY THE A/B AND ITS NULL CONTROL ARE WANTED.
        // The width ladder below is step 1's instrument, its answer is
        // recorded, and it is opt-in so a hold cannot spend minutes on
        // it through a flag that was not parsed the way it was meant.
        if !ladder_wanted {
            continue;
        }

        println!(
            "  {:>5} {:>7} {:>11} {:>9} {:>8} {:>7} {:>10} {:>10} {:>10} {:>10}",
            "width",
            "overlap",
            "wall ms",
            "cpu s",
            "thr-w",
            "lanes",
            "apply busy",
            "apply wait",
            "lane dec",
            "lane wait"
        );
        for overlap in [true, false] {
            for width in WIDTHS {
                rarkit::probe::reset_peak_lanes();
                rarkit::probe::reset_pipeline_split();
                let (wall, cpu) = cell(REPS, || {
                    rarkit::internals::rar5::extract_scheduled(&archive, width, None, overlap)
                        .expect("rarkit extracts");
                });
                let lanes = rarkit::probe::peak_lanes();
                let (waits, wait_ns, busy_ns, lane_waits, lane_wait_ns, lane_decode_ns) =
                    rarkit::probe::pipeline_split();
                let reps = REPS as f64;
                let ms = |ns: u64| ns as f64 * 1e-6 / reps;
                println!(
                    "  {:>5} {:>7} {:>11.2} {:>9.4} {:>8.2} {:>7} {:>9.2}m {:>9.2}m {:>9.2}m \
                     {:>9.2}m   ({waits} waits, {lane_waits} hand-overs)",
                    width,
                    if overlap { "on" } else { "off" },
                    wall.as_secs_f64() * 1e3,
                    cpu,
                    cpu / wall.as_secs_f64(),
                    lanes,
                    ms(busy_ns),
                    ms(wait_ns),
                    ms(lane_decode_ns),
                    ms(lane_wait_ns),
                );
            }
        }
    }
}
