//! The width ladder that fills in API 8.4.3's PROVISIONAL read ceiling.
//!
//! 8.4.2 gave the read side its own thread dial, `ReadOptions::workers`,
//! and 8.4.3 says the engine's own ceiling behind `None` is A MEASURED
//! CONSTANT: whichever width measures the lowest wall inside the caller's
//! memory ceiling. Until a run fills it in, what ships is
//! the pool's width. This example is the one leg of that run that a
//! command line cannot reach: it sets `workers` EXPLICITLY, one width per
//! process, and prints the wall, the peak working memory and the lane
//! counts beside it.
//!
//! the read width script drives it. ONE PROCESS PER CELL, so
//! `/usr/bin/time -l`'s peak RSS is that width's and not the largest
//! child a driver ever reaped.
//!
//! Not a gate leg, and no ratio against the old engine is implied: this
//! times ONE engine against itself across widths, the way
//! `breadth_lanes.rs` times it across arrangements. The ceiling a ratio
//! IS quoted against here is the UNBOUNDED arrangement (`--arm 0`, each
//! member at the whole ceiling), which 8.4.5 rejected for shipping and
//! 8.4.3 names as the ceiling to quote.
//!
//! **What this cannot show above a width of eight.** The RAR 5 tape
//! decode carries `MT_MAX_WORKERS` of 8 (`carry/c_lz/codec/rar50.rs`),
//! and `tape::workers` mins the width against it, so ONE member's lanes
//! stop at eight however wide the dial is set. A shape whose breadth is
//! one - `one-big-many-small`, and a solid set, which is breadth one by
//! the format - therefore cannot move above eight for a reason that is
//! not the dial's. That ceiling is in contract, 8.4 is silent on it, and
//! this harness reports it rather than changing it.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rarkit::{
    extract_parallel, memory, probe, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Payload, RangeSource, ReadOptions, Result, WriteMethod, WriteOptions, Writer,
};

/// The shapes 8.4.3 names, as `(member size, how many, small size, how
/// many small)`.
///
/// The first four are the earlier breadth cross, kept byte for byte as
/// `breadth_lanes.rs` builds them so that this table and the one 8.4 was
/// written on are read side by side. `eight-64` is the non-solid half of
/// the `READ_CAP` re-measurement, built here as well so the engine's
/// ceiling and the tool's pool cap are read on the same shape in the same
/// run. The solid volume set is the fifth shape and is NOT built
/// here: it is the reference `rar`'s to build, so the block chain is the
/// reference's, and the driver passes its volumes in as several sources.
fn shape(name: &str) -> (usize, usize, usize, usize) {
    match name {
        "eight-16" => (16 << 20, 8, 0, 0),
        "two-256" => (256 << 20, 2, 0, 0),
        "one-big-many-small" => (256 << 20, 1, 64 << 10, 2000),
        "sixteen-64" => (64 << 20, 16, 0, 0),
        "eight-64" => (64 << 20, 8, 0, 0),
        other => panic!("unknown shape {other}"),
    }
}

/// Material an `-m3` leg can be read off: about half of it compresses and
/// half does not. Copied in shape and in seed from `breadth_lanes.rs`, so
/// a cell here and a cell there decode the same bytes.
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

fn build(name: &str, path: &std::path::Path) {
    let (big, bigs, small, smalls) = shape(name);
    let big_body = body(big, 1);
    let small_body = if smalls > 0 {
        body(small, 2)
    } else {
        Vec::new()
    };
    let names: Vec<Vec<u8>> = (0..bigs)
        .map(|i| format!("big{i}.dat").into_bytes())
        .chain((0..smalls).map(|i| format!("small{i}.dat").into_bytes()))
        .collect();

    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    for (i, name) in names.iter().enumerate() {
        let payload = if i < bigs { &big_body } else { &small_body };
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

/// Verifies and counts, and keeps no bytes: these shapes run to a
/// gigabyte and holding the output would measure the harness.
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 4 && args[1] == "build" {
        build(&args[2], std::path::Path::new(&args[3]));
        return;
    }
    if args.len() < 6 {
        eprintln!(
            "usage: read_width_sweep build <shape> <path>\n       \
             read_width_sweep run <width|none> <breadth> <arm> <volume>..."
        );
        std::process::exit(2);
    }
    // `none` is the engine's own default, which is what a caller who sets
    // nothing gets and what 8.4.3's constant lives behind. Any other value
    // is `Some(n)`, taken exactly: that is the whole point of the dial.
    let workers = match args[2].as_str() {
        "none" => None,
        n => Some(n.parse::<usize>().expect("width")),
    };
    let breadth: usize = args[3].parse().expect("breadth");
    let arm: u8 = args[4].parse().expect("arm");
    let paths: Vec<&String> = args[5..].iter().collect();

    probe::set_breadth_arm(arm);
    let opts = ReadOptions::default().with_workers(workers);
    // The pool is the caller's and is left at the box's own width, so that
    // the width under test is the binding term and not the pool (8.4.3).
    let sources: Vec<Arc<dyn RangeSource>> = paths
        .iter()
        .map(|p| Arc::new(std::fs::File::open(p).expect("open")) as Arc<dyn RangeSource>)
        .collect();
    let sink = Blackhole {
        bytes: AtomicU64::new(0),
    };

    memory::reset_peak();
    probe::reset_peak_lanes();
    probe::reset_peak_members();
    probe::reset_peak_workers();
    let started = Instant::now();
    let report = extract_parallel(sources, &opts, &sink, breadth).expect("extract_parallel");
    let wall = started.elapsed().as_secs_f64();

    // One line of `key=value`, so the driver parses it without a format.
    println!(
        "RESULT wall={wall:.4} members={} bytes={} resolved={} \
         peak_lanes={} peak_members={} peak_workers={} peak_working={} \
         engine_peak={} limit={}",
        report.members,
        sink.bytes.load(Ordering::Relaxed),
        opts.read_width(),
        probe::peak_lanes(),
        probe::peak_members(),
        probe::peak_workers(),
        report.peak_working_memory,
        memory::peak(),
        opts.memory.working_limit,
    );
}
