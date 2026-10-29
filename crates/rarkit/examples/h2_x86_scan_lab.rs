//! What the RAR 5 x86 address pass costs, and where inside it.
//!
//! The 21 Sep profile puts `x86_pass` at 11.6 percent of
//! `rar5_code_32m_m3_serial` - the largest block of that leg outside the
//! symbol loop, and the leg fails the 0.97x gate where its unfiltered twin
//! does not. This lab prices the visiting form against the one-walk form
//! over the same bytes in ONE binary in the same minutes, which is the
//! only comparison a loaded box can carry.
//!
//! Arm 0 is the walking form this package shipped until 21 Sep 2026 and
//! arm 1 the scan-then-convert form it ships now.
//!
//! It runs over `target/bench-h2/code.dat`, the code leg's own corpus,
//! in spans the size the leg's filter records name. Every arm is checked
//! byte for byte against the first before any of them is timed.

use std::time::Instant;

fn main() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    let data = std::fs::read(dir.join("code.dat"))
        .expect("run `cargo bench -p rarkit --bench two_arm rar5_code_32m_m3` once first");
    let span: usize = std::env::args()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(65_536);
    let rounds: usize = std::env::args()
        .nth(2)
        .and_then(|n| n.parse().ok())
        .unwrap_or(9);
    println!(
        "code.dat {} bytes, span {span}, {rounds} rounds",
        data.len()
    );

    for jump in [false, true] {
        // Correctness first: the two forms must write the same bytes.
        let mut want = Vec::new();
        for arm in 0..2u8 {
            let mut work = data.clone();
            for (index, chunk) in work.chunks_mut(span).enumerate() {
                rarkit::internals::rar5::rar5_x86_pass(chunk, (index * span) as u32, jump, arm);
            }
            if arm == 0 {
                assert_ne!(work, data, "the pass changed something, jump {jump}");
                want = work;
            } else {
                assert_eq!(
                    want, work,
                    "arm {arm} disagrees with the shipped walk, jump {jump}"
                );
            }
        }

        // Alternated, so a drift inside the run hits both arms.
        let mut best = [f64::MAX; 2];
        for _ in 0..rounds {
            for arm in 0..2u8 {
                let mut work = data.clone();
                let start = Instant::now();
                for (index, chunk) in work.chunks_mut(span).enumerate() {
                    rarkit::internals::rar5::rar5_x86_pass(chunk, (index * span) as u32, jump, arm);
                }
                let took = start.elapsed().as_secs_f64();
                std::hint::black_box(&work);
                if took < best[arm as usize] {
                    best[arm as usize] = took;
                }
            }
        }
        let ns = |t: f64| t * 1e9 / data.len() as f64;
        println!(
            "jump {jump}: walking {:.3} ms ({:.3} ns/B), split {:.3} ms ({:.3} ns/B), \
             walking/split {:.3}x",
            best[0] * 1e3,
            ns(best[0]),
            best[1] * 1e3,
            ns(best[1]),
            best[0] / best[1],
        );
    }
}
