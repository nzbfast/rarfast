//! THE SYMBOL PASS'S PIPELINE SPLIT, untimed.
//!
//! One member of a cached `two_arm` corpus decoded on the tape path at a
//! fixed width, round after round, printing per round the member's wall,
//! the apply stage's busy and waiting time and the lanes' summed decode
//! time (which, with the pass on, includes each lane's symbol build), from
//! `probe::pipeline_split`. The knob `RARKIT_SYMBOL_PASS` is read ONCE a
//! process, so a pair is two processes, one each way, alternated by the
//! caller (its driver script). No old engine is linked in and
//! nothing here is a gate figure.
//!
//! Usage: `cargo run --release -p rarkit --features bench-internals,test-support
//! --example h2_md128k_symbol_lab -- <corpus> [width] [rounds]`, reading
//! `target/bench-h2/<corpus>.rar`.

#[cfg(all(feature = "bench-internals", feature = "test-support"))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = args
        .first()
        .cloned()
        .unwrap_or_else(|| "text_64m_m5_md128k".into());
    let width: usize = args.get(1).and_then(|w| w.parse().ok()).unwrap_or(8);
    let rounds: usize = args.get(2).and_then(|r| r.parse().ok()).unwrap_or(9);
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    let archive =
        std::fs::read(dir.join(format!("{corpus}.rar"))).expect("the cached corpus reads");
    let on = std::env::var("RARKIT_SYMBOL_PASS").unwrap_or_default();
    // One discarded round: the pool, the lanes' buffers, the pages.
    rarkit::internals::rar5::extract_scheduled(&archive, width, None, true).expect("decodes");
    let mut rows = Vec::new();
    for _ in 0..rounds {
        rarkit::probe::reset_pipeline_split();
        let t = std::time::Instant::now();
        let out = rarkit::internals::rar5::extract_scheduled(&archive, width, None, true)
            .expect("decodes");
        let wall = t.elapsed().as_secs_f64() * 1e3;
        std::hint::black_box(out);
        let (_, wait_ns, busy_ns, _, lane_wait_ns, lane_ns) = rarkit::probe::pipeline_split();
        rows.push([
            wall,
            busy_ns as f64 * 1e-6,
            wait_ns as f64 * 1e-6,
            lane_ns as f64 * 1e-6,
            lane_wait_ns as f64 * 1e-6,
        ]);
    }
    let median = |i: usize| {
        let mut v: Vec<f64> = rows.iter().map(|r| r[i]).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    println!(
        "symbol-lab corpus={corpus} pass={on} width={width} rounds={rounds} wall_ms={:.2} apply_busy_ms={:.2} apply_wait_ms={:.2} lane_ms={:.2} lane_handover_wait_ms={:.2}",
        median(0),
        median(1),
        median(2),
        median(3),
        median(4)
    );
}

#[cfg(not(all(feature = "bench-internals", feature = "test-support")))]
fn main() {
    eprintln!("REFUSING: build with --features bench-internals,test-support");
    std::process::exit(2);
}
