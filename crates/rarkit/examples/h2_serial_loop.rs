//! Decode one cached H2 archive SERIALLY, over and over, so a sampler has
//! something to attach to.
//!
//! Only rarkit's own arm runs here: the oracle arm is a black box that
//! is timed and never instrumented. Nothing here is timed either; the
//! wall it prints is a progress line, not a figure.
//!
//! Usage: `h2_serial_loop <archive.rar> [passes]`.

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("an archive path");
    let passes: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(20usize);
    let archive = std::fs::read(&path).expect("the archive reads");
    let start = std::time::Instant::now();
    let mut total = 0u64;
    for _ in 0..passes {
        let members = rarkit::internals::rar5::extract(&archive, false).expect("rarkit extracts");
        for (_, data) in members {
            total += data.len() as u64;
        }
    }
    println!(
        "{path}: {passes} passes, {total} bytes, {:.3} s",
        start.elapsed().as_secs_f64()
    );
}
