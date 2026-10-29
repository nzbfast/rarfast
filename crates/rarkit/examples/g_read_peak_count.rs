//! What a read under a stated budget COUNTS against what the process
//! HOLDS (whole-process accounting; SPEC-API 8).
//!
//! Reads one archive through the public sequential extract, every member
//! written to a null writer as `rarfast p` writes it to stdout, under
//! `MemoryPolicy::from_limit(<limit MiB>)` (0 for the default policy), and
//! prints three figures: the report's `peak_working_memory`, the process
//! counter `memory::peak`, and the process's peak RSS as the kernel saw it.
//! A stated budget is honoured whole-process when the third stays under it;
//! the gap between the first two and the third is what no count sees.
//!
//!     cargo run --release -p rarkit --example g_read_peak_count -- a.rar 128 [breadth]

use rarkit::{Disposition, MemberInfo, MemoryPolicy, RangeSource, ReadOptions, Sink};
use std::sync::Arc;

struct Null;

impl Sink for Null {
    type Out = std::io::Sink;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(std::io::sink()))
    }
}

impl rarkit::ParallelSink for Null {
    type Out = std::io::Sink;

    fn open(&self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(std::io::sink()))
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn peak_rss_mib() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `getrusage` fills the struct it is handed and reads nothing
    // else; the struct is zeroed and lives for the call.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    let max = unsafe { usage.assume_init() }.ru_maxrss as f64;
    // Linux reports KiB, macOS bytes.
    if cfg!(target_os = "macos") {
        max / 1_048_576.0
    } else {
        max / 1024.0
    }
}

#[cfg(not(unix))]
fn peak_rss_mib() -> f64 {
    0.0
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: g_read_peak_count <archive> [limit MiB]");
    let limit: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(0);
    let mut opts = ReadOptions::default();
    if limit > 0 {
        opts = opts.with_memory(MemoryPolicy::from_limit(limit << 20));
    }
    let file: Arc<dyn RangeSource> = Arc::new(std::fs::File::open(&path).expect("open archive"));
    // The one-member minimum, under this policy's terms.
    let minimum = rarkit::Archive::open(Arc::clone(&file), &opts)
        .map(|archive| archive.minimum_working_memory(&opts.memory))
        .unwrap_or(0);
    println!(
        "{path}: minimum_working_memory {:.1} MiB",
        minimum as f64 / 1_048_576.0
    );
    rarkit::memory::reset_peak();
    // A third argument, a breadth, reads through `extract_parallel` as
    // rarfast's `t` and `x` do on a non-solid set.
    let breadth: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(0);
    // A fourth, the width (ReadOptions::workers).
    if let Some(width) = args.next().and_then(|a| a.parse().ok()) {
        opts = opts.with_workers(Some(width));
    }
    let report = if breadth > 0 {
        rarkit::extract_parallel(vec![file], &opts, &Null, breadth).expect("extract_parallel")
    } else {
        rarkit::extract(vec![file], &opts, &mut Null, &mut ()).expect("extract")
    };
    let mib = |b: u64| b as f64 / 1_048_576.0;
    println!(
        "{path} limit {limit} MiB: members {} bytes {} | report peak {:.1} MiB | memory::peak {:.1} MiB | peak RSS {:.1} MiB",
        report.members,
        report.bytes,
        mib(report.peak_working_memory),
        mib(rarkit::memory::peak()),
        peak_rss_mib()
    );
}
