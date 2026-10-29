//! Why a non-solid many-member read runs near one core on Windows, asked
//! of the engine directly rather than through the command line.
//!
//! The Windows rivals run read `rarfast t` at 1.06 cores over a 2,571
//! member non-solid `-m5` archive on 16 logical processors, where the
//! same-shaped archive reads about four cores on Linux. This probe runs the
//! same entry point the command line's `t` runs, `extract_parallel` into a
//! sink that keeps nothing, and varies ONE thing at a time:
//!
//! - `file`: the archive as a `std::fs::File`, which is what the command
//!   line hands the engine, read through `RangeSource for File`;
//! - `mem`: the whole archive read into memory first, so no read reaches
//!   the operating system at all during the decode;
//! - `reopen`: one `File` per thread, opened on first use, so no two
//!   threads ever share a handle.
//!
//! Each source is wrapped in a counter that records the calls, the bytes,
//! the nanoseconds spent inside `read_at` summed over every thread, and the
//! most threads ever inside `read_at` at once. Beside that it prints the
//! engine's own `probe` counters: the most members in flight, the most tape
//! lanes alive, and the walking thread's parked waits.
//!
//! It is a PROBE and not a gate leg: one process, no old arm, no ratio.
//!
//!     cargo run --release --features test-support \
//!         --example w_windows_width_probe -- ARCHIVE file|mem|reopen WIDTH REPS [LIMIT_MIB]
//!
//! LIMIT_MIB, when given, replaces the default memory policy with
//! `MemoryPolicy::from_limit` of that many MiB, so the admission the pool
//! applies against `working_limit` can be moved on its own.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rarkit::{Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource, ReadOptions};

/// A sink that keeps nothing, the `t` command's shape.
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

/// What every read through a [`Counted`] source added up to.
#[derive(Default)]
struct Tally {
    calls: AtomicU64,
    bytes: AtomicU64,
    nanos: AtomicU64,
    inside: AtomicUsize,
    peak_inside: AtomicUsize,
}

/// A source that counts what the engine asks of the one inside it.
struct Counted<S> {
    inner: S,
    tally: Arc<Tally>,
}

impl<S: RangeSource> RangeSource for Counted<S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let now = self.tally.inside.fetch_add(1, Ordering::Relaxed) + 1;
        self.tally.peak_inside.fetch_max(now, Ordering::Relaxed);
        let started = Instant::now();
        let got = self.inner.read_at(offset, buf);
        let spent = started.elapsed().as_nanos() as u64;
        self.tally.inside.fetch_sub(1, Ordering::Relaxed);
        self.tally.calls.fetch_add(1, Ordering::Relaxed);
        self.tally.nanos.fetch_add(spent, Ordering::Relaxed);
        if let Ok(n) = got {
            self.tally.bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
        got
    }
    fn available(&self) -> u64 {
        self.inner.available()
    }
    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

/// One handle per thread, opened on that thread's first read.
struct Reopen {
    path: std::path::PathBuf,
    len: u64,
    handles: Mutex<HashMap<std::thread::ThreadId, Arc<std::fs::File>>>,
}

impl RangeSource for Reopen {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let id = std::thread::current().id();
        let file = {
            let mut map = self.handles.lock().expect("handle map");
            match map.get(&id) {
                Some(f) => Arc::clone(f),
                None => {
                    let f = Arc::new(std::fs::File::open(&self.path)?);
                    map.insert(id, Arc::clone(&f));
                    f
                }
            }
        };
        file.read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        self.len
    }
    fn len(&self) -> Option<u64> {
        Some(self.len)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: w_windows_width_probe ARCHIVE file|mem|reopen WIDTH REPS [LIMIT_MIB]");
        std::process::exit(2);
    }
    let path = std::path::PathBuf::from(&args[1]);
    let kind = args[2].as_str();
    let width: usize = args[3].parse().expect("WIDTH");
    let reps: u32 = args[4].parse().expect("REPS");
    let limit: Option<u64> = args
        .get(5)
        .map(|v| v.parse::<u64>().expect("LIMIT_MIB") << 20);

    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(width)
        .build_global();
    let cores = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    println!(
        "box: available_parallelism {cores}, rayon pool {}, width {width}, source {kind}",
        rayon::current_num_threads()
    );

    let len = std::fs::metadata(&path).expect("archive").len();
    let whole: Option<Arc<Vec<u8>>> = if kind == "mem" {
        Some(Arc::new(std::fs::read(&path).expect("read archive")))
    } else {
        None
    };

    for rep in 0..reps {
        let tally = Arc::new(Tally::default());
        let source: Arc<dyn RangeSource> = match kind {
            "file" => Arc::new(Counted {
                inner: std::fs::File::open(&path).expect("open"),
                tally: Arc::clone(&tally),
            }),
            "mem" => Arc::new(Counted {
                inner: Arc::clone(whole.as_ref().expect("whole")),
                tally: Arc::clone(&tally),
            }),
            "reopen" => Arc::new(Counted {
                inner: Reopen {
                    path: path.clone(),
                    len,
                    handles: Mutex::new(HashMap::new()),
                },
                tally: Arc::clone(&tally),
            }),
            other => panic!("unknown source {other}"),
        };
        rarkit::probe::reset_peak_workers();
        rarkit::probe::reset_peak_members();
        rarkit::probe::reset_peak_lanes();
        rarkit::probe::reset_walk_stalls();
        rarkit::probe::reset_pool_handoffs();
        rarkit::probe::reset_lane_grants();
        let mut opts = ReadOptions::default().with_workers(Some(width));
        if let Some(bytes) = limit {
            opts = opts.with_memory(rarkit::MemoryPolicy::from_limit(bytes));
        }
        let started = Instant::now();
        let report = rarkit::extract_parallel(vec![source], &opts, &Null, width).expect("extract");
        let wall = started.elapsed().as_secs_f64();
        let (stalls, stall_nanos) = rarkit::probe::walk_stalls();
        println!(
            "rep {rep} source {kind} width {width}: wall {wall:.3} s, members {}, bytes {}, \
             peak members {}, peak workers {}, peak lanes {}, walk stalls {} ({:.3} s), \
             handoffs {}, reads {} ({} MiB, mean {} B), time inside reads {:.3} s, \
             most threads inside a read at once {}",
            report.members,
            report.bytes,
            rarkit::probe::peak_members(),
            rarkit::probe::peak_workers(),
            rarkit::probe::peak_lanes(),
            stalls,
            stall_nanos as f64 / 1e9,
            rarkit::probe::pool_handoffs(),
            tally.calls.load(Ordering::Relaxed),
            tally.bytes.load(Ordering::Relaxed) >> 20,
            tally.bytes.load(Ordering::Relaxed) / tally.calls.load(Ordering::Relaxed).max(1),
            tally.nanos.load(Ordering::Relaxed) as f64 / 1e9,
            tally.peak_inside.load(Ordering::Relaxed),
        );
        let trim = |v: Vec<u64>| {
            let end = v.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
            v[..end].to_vec()
        };
        println!(
            "  working limit {} MiB; lane grants by lanes granted {:?}; by members live {:?}",
            opts.memory.working_limit >> 20,
            trim(rarkit::probe::lane_grants()),
            trim(rarkit::probe::lane_grant_live()),
        );
    }
}
