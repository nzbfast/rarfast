//! Why `one-big-many-small` is BIMODAL at narrow read widths on twenty
//! cores.
//!
//! The finding this answers is the read side's
//! default width at TWENTY cores (API 8.4.3): that shape's fifteen
//! repeats do not scatter, they land near 0.45 s and near 0.91 to 1.13 s,
//! the slow share falls as the width rises, CPU seconds move with the
//! mode, and none of it shows on a 32 core box.
//!
//! **What a wall cannot say and this prints instead.** The shape is ONE
//! 256 MiB `-m3` member followed by 2000 of 64 KiB, so it has a decode
//! long enough to hold lanes and two thousand short ones to take them
//! away. Four counters say which of the mechanisms is running:
//!
//! - `decoded` against the report's member count: how many members the
//!   WALK decoded itself, which is the offload floor's question;
//! - `peak_members`: how many were ever decoding at once, which is the
//!   breadth;
//! - the LANE GRANT histogram and the `live` histogram beside it
//!   (`probe::lane_grants`, `probe::lane_grant_live`): what width the
//!   tape decode was actually granted per chunk, and how many members
//!   were decoding when it asked. `read::lanes::LaneBudget` hands out
//!   `ceiling / live`, so a big member sharing an archive with small
//!   ones re-takes its width once per chunk against a number the small
//!   ones move;
//! - `planned` (chunks, blocks): whether a narrow grant makes the decode
//!   plan the same bytes more than once;
//! - `walk_stalls` (waits, nanoseconds): head-of-line blocking, since the
//!   flight queue retires from the FRONT and this archive's first member
//!   is by far its longest.
//!
//! Every counter is `test-support` only and the shipped engine is
//! untouched by this probe.
//!
//! Usage:
//!
//!     f_bimodal_probe build <path>
//!     f_bimodal_probe run <path> <width|none> <breadth> <repeats> [floor]
//!
//! `floor` is `probe::set_offload_floor`, which replaces BOTH offload
//! floors on this thread. It is how the engine AS IT WAS at the run's
//! own revision is reached from the tip: that revision had one floor of 256 KiB
//! for every method, so `262144` is that engine's dispatch rule and
//! `none` is the one that ships. One binary, two configurations, which is
//! the only honest way to set them beside each other.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rarkit::{
    extract_parallel, memory, probe, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Payload, RangeSource, ReadOptions, Result, WriteMethod, WriteOptions, Writer,
};

/// The shape, byte for byte as `examples/read_width_sweep.rs` builds it,
/// so a cell here and a cell in the 8.4.3 ladder decode the same archive.
const BIG: usize = 256 << 20;
const SMALL: usize = 64 << 10;
const SMALLS: usize = 2000;

/// About half of it compresses and half does not. Copied in shape and in
/// seed from `read_width_sweep.rs` for the same reason.
fn body(bytes: usize, salt: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 128);
    let mut seed = 0x2026_0920_u64 ^ salt;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

fn build(path: &std::path::Path) {
    let big_body = body(BIG, 1);
    let small_body = body(SMALL, 2);
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = std::iter::once(b"big0.dat".to_vec())
        .chain((0..SMALLS).map(|i| format!("small{i}.dat").into_bytes()))
        .collect();
    for (i, name) in names.iter().enumerate() {
        let payload = if i == 0 { &big_body } else { &small_body };
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(payload),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = std::fs::File::create(path).expect("create");
    writer.finish_into(&mut out).expect("finish");
    out.flush().expect("flush");
}

struct Blackhole {
    bytes: AtomicU64,
}

struct Counted(u64);

impl Write for Counted {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0 += data.len() as u64;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ParallelSink for Blackhole {
    type Out = Counted;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Counted>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Counted(0)))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        out: Option<Counted>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "a member this harness read failed its checksum"
        );
        self.bytes
            .fetch_add(out.map_or(0, |c| c.0), Ordering::Relaxed);
        Ok(())
    }
}

/// This process's CPU seconds and peak RSS in bytes.
///
/// `RUSAGE_SELF`, never `RUSAGE_CHILDREN`, which reports the largest
/// child ever reaped and once put an archive builder's figure on every
/// row of a table here (19 Sep). The CPU figure is
/// differenced across one repeat; the RSS is a high-water mark and never
/// falls, so it is the PROCESS's and a cell that wants a repeat's own
/// peak runs one repeat per process.
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
    // Bytes on macOS, KiB on Linux.
    let scale = if cfg!(target_os = "macos") {
        1.0
    } else {
        1024.0
    };
    (t(ru.ru_utime) + t(ru.ru_stime), ru.ru_maxrss as f64 * scale)
}

/// Nowhere to ask: `make cross` builds this example for
/// `x86_64-pc-windows-gnu`, which has no `getrusage`, and a bench that
/// only ever runs on a Mac still has to COMPILE there. `NaN`
/// rather than zero, so a figure from a box that cannot measure is not
/// mistaken for a measurement of nothing. The same arm and the same
/// reason as the width bench.
#[cfg(not(unix))]
fn usage() -> (f64, f64) {
    (f64::NAN, f64::NAN)
}

/// A histogram as `bucket:count` pairs, empty buckets left out.
fn hist(counts: &[u64]) -> String {
    let mut out = String::new();
    for (n, &c) in counts.iter().enumerate() {
        if c == 0 {
            continue;
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!("{n}:{c}"));
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "build" {
        build(std::path::Path::new(&args[2]));
        return;
    }
    if args.len() < 6 {
        eprintln!(
            "usage: f_bimodal_probe build <path>\n       \
             f_bimodal_probe run <path> <width|none> <breadth> <repeats>"
        );
        std::process::exit(2);
    }
    let path = &args[2];
    let workers = match args[3].as_str() {
        "none" => None,
        n => Some(n.parse::<usize>().expect("width")),
    };
    let breadth: usize = args[4].parse().expect("breadth");
    let repeats: usize = args[5].parse().expect("repeats");
    let floor = match args.get(6).map(String::as_str) {
        None | Some("none") => None,
        Some(n) => Some(n.parse::<u64>().expect("floor")),
    };
    probe::set_offload_floor(floor);

    let opts = ReadOptions::default().with_workers(workers);
    for rep in 0..repeats {
        let sources: Vec<Arc<dyn RangeSource>> =
            vec![Arc::new(std::fs::File::open(path).expect("open")) as Arc<dyn RangeSource>];
        let sink = Blackhole {
            bytes: AtomicU64::new(0),
        };
        memory::reset_peak();
        probe::reset();
        probe::reset_peak_lanes();
        probe::reset_peak_members();
        probe::reset_lane_grants();
        probe::reset_planned();
        probe::reset_walk_stalls();
        let (cpu0, _) = usage();
        let started = Instant::now();
        let report = extract_parallel(sources, &opts, &sink, breadth).expect("extract_parallel");
        let wall = started.elapsed().as_secs_f64();
        let (cpu1, rss) = usage();
        let (chunks, blocks) = probe::planned();
        let (waits, stall_ns) = probe::walk_stalls();
        println!(
            "REP rep={rep} width={} floor={} wall={wall:.4} members={} walked={} \
             cpu={:.3} rssMiB={:.1} peak_members={} peak_lanes={} chunks={chunks} blocks={blocks} \
             waits={waits} stall_ms={:.1} lanes=[{}] live=[{}] bytes={}",
            opts.read_width(),
            floor.map_or("none".to_string(), |n| n.to_string()),
            report.members,
            probe::decoded_members(),
            cpu1 - cpu0,
            rss / (1024.0 * 1024.0),
            probe::peak_members(),
            probe::peak_lanes(),
            stall_ns as f64 / 1e6,
            hist(&probe::lane_grants()),
            hist(&probe::lane_grant_live()),
            sink.bytes.load(Ordering::Relaxed),
        );
    }
}
