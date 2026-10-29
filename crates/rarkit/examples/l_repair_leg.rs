//! One inline repair through the public API: read a
//! damaged RAR 5 volume positionally, write the mended volume, and print
//! one TSV row of wall, CPU seconds, peak RSS and the report. There is no
//! command-line `r` yet, so this is the repair leg's driver.
//!
//!     cargo run --release --example l_repair_leg -- <damaged> <out> [workers]
//!
//! `workers` is `MemoryPolicy::max_workers` (default: the default
//! policy's). One repair per process, so the peak RSS is this repair's.

use std::io::Write;
use std::time::Instant;

/// This process's CPU seconds and peak RSS in bytes (`RUSAGE_SELF`).
#[cfg(unix)]
fn usage() -> (f64, f64) {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given; RUSAGE_SELF is valid.
    #[allow(unsafe_code)]
    let ru = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr());
        ru.assume_init()
    };
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    let scale = if cfg!(target_os = "macos") {
        1.0
    } else {
        1024.0
    };
    (t(ru.ru_utime) + t(ru.ru_stime), ru.ru_maxrss as f64 * scale)
}

#[cfg(not(unix))]
fn usage() -> (f64, f64) {
    (f64::NAN, f64::NAN)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: l_repair_leg <damaged> <out> [workers]");
        std::process::exit(2);
    }
    let src = std::fs::File::open(&args[1]).expect("open the damaged volume");
    let mut opts = rarkit::ReadOptions::default();
    if let Some(workers) = args.get(3) {
        opts.memory.max_workers = workers.parse().expect("workers");
    }
    let file = std::fs::File::create(&args[2]).expect("create the output");
    let mut out = std::io::BufWriter::with_capacity(1 << 20, file);
    let t = Instant::now();
    let report = rarkit::recovery::repair_inline(&src, &opts, &mut out);
    out.flush().expect("flush");
    let wall = t.elapsed().as_secs_f64();
    let (cpu, rss) = usage();
    match report {
        Ok(report) => println!(
            "repair\twall {wall:.3}\tcpu {cpu:.3}\trss_mib {:.1}\tworkers {}\trebuilt {:?}\tfailed {:?}\tpeak_work_mib {:.1}",
            rss / 1048576.0,
            opts.memory.max_workers,
            report.rebuilt,
            report.failed,
            report.peak_working_memory as f64 / 1048576.0
        ),
        Err(err) => {
            println!("repair\twall {wall:.3}\tcpu {cpu:.3}\terror {err}");
            std::process::exit(1);
        }
    }
}
