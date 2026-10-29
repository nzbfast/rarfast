//! Where the seconds go on an archive of MANY SMALL COMPRESSED members.
//!
//! The tool-level round of 20 Sep 2026 found `rarkit-cli` three to four
//! times the old engine's wall on a source tree of about four thousand
//! members, with its CPU seconds equal to its wall - one core, start to
//! finish - and no response at all to `-mt`. This is what answers why:
//! it runs `extract_parallel` over the bench harness's own `src4k`
//! corpus at a width and an offload floor the caller names, and prints
//! the four counters that say what the pool actually did.
//!
//! It is a PROBE and not a gate leg. It has no old arm, it takes one
//! sample, and a figure from it belongs in a paragraph of prose beside
//! the sweep that settled the question, never in a ratio table.
//!
//!     cargo run --release --example f_many_small_probe -- \
//!         target/bench-f/f_src4m3.rar 8 32768 50
//!
//! The corpus is the bench's: run `two_arm src4k` once to write it.

use std::sync::Arc;
use std::time::Instant;

use rarkit::{Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource, ReadOptions};

/// A sink that keeps nothing: the probe is about where the TIME goes, and
/// holding 230 MB of output would put an allocator in the middle of it.
struct Null;

impl ParallelSink for Null {
    type Out = Count;

    fn open(&self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Count>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Count(0)))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        _out: Option<Count>,
        _outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        Ok(())
    }
}

struct Count(u64);

impl std::io::Write for Count {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0 += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// This process's own CPU seconds, user plus system.
///
/// `RUSAGE_SELF`, never `RUSAGE_CHILDREN`, which reports the largest child
/// ever reaped and put an archive builder's figure on every row of one
/// table (19 Sep).
#[cfg(unix)]
fn cpu_seconds() -> f64 {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given; RUSAGE_SELF is valid.
    #[allow(unsafe_code)]
    let ru = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr());
        ru.assume_init()
    };
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    t(ru.ru_utime) + t(ru.ru_stime)
}

#[cfg(not(unix))]
fn cpu_seconds() -> f64 {
    f64::NAN
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: f_many_small_probe <archive> [width] [offload floor] [settle spin us]");
        std::process::exit(2);
    });
    let width: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(8);
    let floor: Option<u64> = args.next().and_then(|a| a.parse().ok());
    let spin: Option<u64> = args.next().and_then(|a| a.parse().ok());
    rarkit::probe::set_offload_floor(floor);
    rarkit::probe::set_settle_spin(spin);

    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let archive = bytes.len() as f64;
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes) as Arc<dyn RangeSource>];

    rarkit::probe::reset();
    rarkit::probe::reset_peak_lanes();
    rarkit::probe::reset_peak_members();
    rarkit::probe::reset_pool_handoffs();
    let cpu_before = cpu_seconds();
    let started = Instant::now();
    let report = rarkit::extract_parallel(sources, &ReadOptions::default(), &Null, width)
        .expect("the corpus extracts");
    let wall = started.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu_before;

    println!(
        "width {width} floor {:?} spin {:?}: wall {:.3} s, cpu {:.3} s, cpu/wall {:.2}",
        floor,
        spin,
        wall,
        cpu,
        cpu / wall
    );
    println!(
        "  {} members, {} bytes out of a {:.1} MiB archive, {:.0} MB/s",
        report.members,
        report.bytes,
        archive / (1024.0 * 1024.0),
        report.bytes as f64 / wall / 1e6
    );
    println!(
        "  decoded ON THE WALKING THREAD: {}   members at once, peak: {}",
        rarkit::probe::decoded_members(),
        rarkit::probe::peak_members()
    );
    println!(
        "  tape lanes at once, peak: {}   pool handoffs: {}",
        rarkit::probe::peak_lanes(),
        rarkit::probe::pool_handoffs()
    );
    println!(
        "  peak working memory: {} bytes",
        report.peak_working_memory
    );
}
