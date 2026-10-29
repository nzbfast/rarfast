//! The RAR 5 SERIAL decode, counted per symbol rather than timed.
//!
//! Only rarkit's own arm runs here: the oracle arm is a black box a
//! run times and never instruments. The
//! wall this prints is a progress line on an untimed box, not a figure.
//!
//! `h2_serial_counters census <archive.rar>` prints the stream's symbol
//! mix, which is the same on every box.
//!
//! `h2_serial_counters run <archive.rar> <passes>` decodes the archive
//! serially `passes` times, the same call the `_serial` legs' rarkit arm
//! makes. Run it under a process counter twice, at `passes` and at 0,
//! and subtract, so reading the archive falls outside the difference:
//! `perf stat` on Linux, `/usr/bin/time -l` on macOS, which prints the
//! process's instructions retired and cycles elapsed.

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("census | run");
    let path = args.next().expect("an archive path");
    let archive = std::fs::read(&path).expect("the archive reads");
    match mode.as_str() {
        "census" => {
            let c = rarkit::internals::rar5::census(&archive).expect("census");
            println!(
                "{path}: bytes {} symbols {} ops {} literals {} matches {} repeats {} filters {}",
                c.bytes, c.symbols, c.operations, c.literals, c.matches, c.repeats, c.filters
            );
        }
        "run" => {
            let passes: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(20);
            let start = std::time::Instant::now();
            let mut total = 0u64;
            for _ in 0..passes {
                let members =
                    rarkit::internals::rar5::extract(&archive, false).expect("rarkit extracts");
                for (_, data) in members {
                    total += data.len() as u64;
                }
            }
            let wall = start.elapsed().as_secs_f64();
            println!("{path}: {passes} passes, {total} bytes, {wall:.3} s");
        }
        other => panic!("unknown mode {other}"),
    }
}
