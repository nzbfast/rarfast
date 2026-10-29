//! ONE DECODE LANE'S WORK ON md128k, SPLIT, untimed.
//!
//! Every block of the first member of a cached `two_arm` corpus decoded
//! into a tape and then built into symbols by the symbol pass, serially on
//! this thread, each part timed (`internals::rar5::lane_split`). Two arms
//! alternated round by round: the symbols REUSED block to block (a lane's
//! steady state) and made FRESH for every block (so the difference prices
//! allocating and first touching them). Per round the medians of decode
//! and build, per block, per operation and per gathered byte. No old
//! engine is linked in and nothing here is a gate figure.
//!
//! Usage: `cargo run --release -p rarkit --features h2-stage-probe
//! --example h2_md128k_lane_split -- <corpus> [rounds] [arm]`, reading
//! `target/bench-h2/<corpus>.rar`. `arm` is `both` (the default, the two
//! arms alternated and timed), or `decode` or `reused` alone, run for a
//! count of the whole process (`/usr/bin/time -l`), the build's
//! instructions being the difference, or `lean` alone (the lean build,
//! `Symbols::build_lean`). `both` times the lean form as a third arm.

#[cfg(feature = "h2-stage-probe")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = args
        .first()
        .cloned()
        .unwrap_or_else(|| "text_64m_m5_md128k".into());
    let rounds: usize = args.get(1).and_then(|r| r.parse().ok()).unwrap_or(9);
    let arm = args.get(2).cloned().unwrap_or_else(|| "both".into());
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    let archive =
        std::fs::read(dir.join(format!("{corpus}.rar"))).expect("the cached corpus reads");
    let members = rarkit::internals::rar5::members(&archive);
    let m = members
        .iter()
        .find(|m| !m.directory && m.method != 0)
        .expect("a compressed member");
    let run = |mode: u8| {
        rarkit::internals::rar5::lane_split(&m.packed, m.window, m.algorithm, mode)
            .expect("decodes")
    };
    if arm != "both" {
        let mode = match arm.as_str() {
            "decode" => 2,
            "lean" => 3,
            _ => 0,
        };
        let mut last = [0u64; 18];
        for _ in 0..rounds {
            last = run(mode);
        }
        println!(
            "lane-split-count corpus={corpus} arm={arm} rounds={rounds} ops={}",
            last[1]
        );
        return;
    }
    let _ = run(0);
    let _ = run(1);
    let _ = run(3);
    let mut rows: [Vec<[u64; 18]>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for _ in 0..rounds {
        rows[0].push(run(0));
        rows[1].push(run(1));
        rows[2].push(run(3));
    }
    let c = &rows[0][0][8..];
    let copies = (c[2] + c[3] + c[4]).max(1) as f64;
    println!(
        "lane-shape corpus={corpus} lit_runs={} lit_bytes={} copies={} copy_bytes={} no_names={:.3} all_names={:.3} mixed={:.3} common_form={:.3} common_le4={:.3} common_le8={:.3} other_form={:.3}",
        c[0],
        c[1],
        copies,
        c[9],
        c[2] as f64 / copies,
        c[3] as f64 / copies,
        c[4] as f64 / copies,
        c[5] as f64 / copies,
        c[6] as f64 / copies,
        c[7] as f64 / copies,
        c[8] as f64 / copies,
    );
    for (arm, name) in [(0, "reused"), (1, "fresh"), (2, "lean")] {
        let med = |i: usize| {
            let mut v: Vec<u64> = rows[arm].iter().map(|r| r[i]).collect();
            v.sort_unstable();
            v[v.len() / 2]
        };
        let r = rows[arm][0];
        let (decode, build) = (med(2) as f64, med(3) as f64);
        println!(
            "lane-split corpus={corpus} arm={name} rounds={rounds} unpacked={} window={} blocks={} ops={} gathered_blocks={} gathered_bytes={} prefix_ops={} max_symbols={} decode_ms={:.3} build_ms={:.3} build_over_decode={:.3} decode_ns_per_op={:.3} build_ns_per_op={:.3} build_ns_per_gathered_byte={:.4}",
            m.unpacked,
            m.window,
            r[0],
            r[1],
            r[4],
            r[5],
            r[6],
            r[7],
            decode * 1e-6,
            build * 1e-6,
            build / decode,
            decode / r[1] as f64,
            build / r[1] as f64,
            build / r[5].max(1) as f64,
        );
    }
}

#[cfg(not(feature = "h2-stage-probe"))]
fn main() {
    eprintln!("REFUSING: build with --features h2-stage-probe");
    std::process::exit(2);
}
