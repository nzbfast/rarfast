//! What the POOL's per-member dispatch costs on many small compressed
//! members, and which end of the pipeline is the limiter.
//!
//! `f_many_small_probe` beside this one answers whether a member reached
//! a worker at all. This one answers the question after it: the members
//! do reach workers, 4,017 of them, and `f/extract-par-src4k-m3` reads
//! 0.805x with 15.0 us of WALL per member on a corpus whose decode is
//! 73 us a member over a breadth of 8. Only the walking thread touches
//! every member, so either the walk's own serial cost is the 15 us or
//! the walk is waiting for workers, and the two want different levers.
//!
//! Three readings, each printed whether or not it is asked for:
//!
//! 1. the corpus, at a width, an offload floor and a settle spin the
//!    caller names, repeated so one outlier cannot carry it. Beside the
//!    pool's counters it prints `probe::walk_stalls()`: the walk's
//!    PARKED waits for a worker's answer and their nanoseconds, which is
//!    what says which end is the limiter.
//! 2. a `sync_channel(1)` ROUND TRIP, receiver parked against receiver
//!    spinning, with the caller's own gap of work between trips. Per
//!    dispatched member the walk sends a task and reads an answer, so
//!    this is the price of the hand-off itself, measured on the box that
//!    is about to be asked whether a lever is worth having.
//! 3. the same round trip's SEND alone, which is the part the walking
//!    thread pays and therefore the part that shows up in wall.
//!
//! It is a PROBE and not a gate leg: one process, no old arm, no ratio.
//!
//!     cargo run --release --features test-support \
//!         --example f_dispatch_probe -- \
//!         target/bench-f/f_src4m3.rar 8 16384 100 5
//!
//! The corpus is the bench's: run `two_arm src4k` once to write it.

use std::sync::mpsc::{sync_channel, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rarkit::{Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource, ReadOptions};

/// A sink that keeps nothing, so no allocator sits in the middle of the
/// measurement. The same `Null` as `f_many_small_probe`'s, for the same
/// reason.
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

/// This process's own CPU seconds, user plus system. `RUSAGE_SELF`, never
/// `RUSAGE_CHILDREN`, which reports the largest child ever reaped.
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

/// Burn `micros` on this thread without sleeping, the way the walk is busy
/// between two members rather than idle.
fn spin_for(micros: u64) {
    if micros == 0 {
        return;
    }
    let until = Instant::now() + Duration::from_micros(micros);
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}

/// One `sync_channel(1)` round trip, `trips` times, with `gap` microseconds
/// of the caller's own work between them.
///
/// The receiver either parks in `recv` at once, which is what a worker does
/// today, or sweeps `try_recv` for `spin` microseconds first. Returns the
/// whole round trip, the SEND alone and the ANSWER wait alone, all in
/// microseconds per trip: the send is the part a walking thread pays where
/// the answer wait is a wait it has work-starved itself into anyway.
fn round_trip(trips: u32, gap: u64, spin: u64) -> (f64, f64, f64) {
    let (tasks, task_rx) = sync_channel::<u64>(1);
    let (answers, answer_rx) = sync_channel::<u64>(1);
    let worker = std::thread::spawn(move || loop {
        let task = if spin == 0 {
            match task_rx.recv() {
                Ok(t) => t,
                Err(_) => return,
            }
        } else {
            let until = Instant::now() + Duration::from_micros(spin);
            loop {
                match task_rx.try_recv() {
                    Ok(t) => break t,
                    Err(TryRecvError::Disconnected) => return,
                    Err(TryRecvError::Empty) => {}
                }
                if Instant::now() >= until {
                    match task_rx.recv() {
                        Ok(t) => break t,
                        Err(_) => return,
                    }
                }
                std::hint::spin_loop();
            }
        };
        if answers.send(task).is_err() {
            return;
        }
    });

    // One warm trip, so neither side is measured through its first park.
    let _ = tasks.send(0);
    let _ = answer_rx.recv();

    let mut send_ns = 0u128;
    let mut wait_ns = 0u128;
    let whole = Instant::now();
    for i in 0..trips {
        spin_for(gap);
        let at = Instant::now();
        if tasks.send(u64::from(i)).is_err() {
            break;
        }
        let sent = Instant::now();
        send_ns += (sent - at).as_nanos();
        if answer_rx.recv().is_err() {
            break;
        }
        wait_ns += sent.elapsed().as_nanos();
    }
    let whole_ns = whole.elapsed().as_nanos();
    drop(tasks);
    let _ = worker.join();
    let per = f64::from(trips).max(1.0);
    (
        whole_ns as f64 / per / 1000.0 - gap as f64,
        send_ns as f64 / per / 1000.0,
        wait_ns as f64 / per / 1000.0,
    )
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: f_dispatch_probe <archive> [width] [floor] [spin us] [repeats] [gap us]");
        std::process::exit(2);
    });
    let width: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(8);
    let floor: Option<u64> = args.next().and_then(|a| a.parse().ok());
    let spin: Option<u64> = args.next().and_then(|a| a.parse().ok());
    let repeats: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(5);
    let gap: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(15);

    rarkit::probe::set_offload_floor(floor);
    rarkit::probe::set_settle_spin(spin);

    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let archive = bytes.len() as f64 / (1024.0 * 1024.0);
    let source: Arc<dyn RangeSource> = Arc::new(bytes);

    println!("== the corpus: {archive:.1} MiB, width {width}, floor {floor:?}, spin {spin:?} ==");
    for run in 0..repeats {
        rarkit::probe::reset();
        rarkit::probe::reset_peak_members();
        rarkit::probe::reset_walk_stalls();
        let cpu_before = cpu_seconds();
        let started = Instant::now();
        let report = rarkit::extract_parallel(
            vec![Arc::clone(&source)],
            &ReadOptions::default(),
            &Null,
            width,
        )
        .expect("the corpus extracts");
        let wall = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds() - cpu_before;
        let (stalls, stall_ns) = rarkit::probe::walk_stalls();
        let members = report.members.max(1);
        println!(
            "run {run}: wall {:.4} s, cpu {:.4} s, cpu/wall {:.2}, {} members, \
             {:.1} us wall a member",
            wall,
            cpu,
            cpu / wall,
            report.members,
            wall * 1e6 / members as f64
        );
        println!(
            "  walk PARKED {stalls} times for {:.4} s total, {:.1} us a park, \
             {:.0}% of wall; on the walking thread: {}, breadth peak {}",
            stall_ns as f64 / 1e9,
            stall_ns as f64 / 1000.0 / f64::from(stalls.max(1) as u32),
            stall_ns as f64 / 1e9 / wall * 100.0,
            rarkit::probe::decoded_members(),
            rarkit::probe::peak_members()
        );
    }

    println!("== the hand-off, sync_channel(1) round trips, gap {gap} us ==");
    for receiver_spin in [0u64, 25, 50, 100, 200] {
        let (whole, send, wait) = round_trip(20_000, gap, receiver_spin);
        println!(
            "receiver spin {receiver_spin:>3} us: round trip {whole:6.2} us, \
             send {send:5.2} us, answer wait {wait:6.2} us"
        );
    }

    // The WORKER's own sweep, cell by cell, INTERLEAVED: every repeat
    // visits every cell, and the order reverses on odd repeats so a drift
    // inside the run cannot be read as the dial (an
    // ascending dial order once made the dial equal time).
    println!("== the worker sweep, interleaved cells, {repeats} repeats a cell ==");
    let cells = [0u64, 25, 50, 100, 200];
    let mut on_the_walk: Option<u64> = None;
    let mut walls: Vec<Vec<f64>> = vec![Vec::new(); cells.len()];
    let mut cpus: Vec<Vec<f64>> = vec![Vec::new(); cells.len()];
    for run in 0..repeats {
        let forward = run % 2 == 0;
        for step in 0..cells.len() {
            let at = if forward {
                step
            } else {
                cells.len() - 1 - step
            };
            rarkit::probe::set_task_spin(Some(cells[at]));
            rarkit::probe::reset();
            let cpu_before = cpu_seconds();
            let started = Instant::now();
            let report = rarkit::extract_parallel(
                vec![Arc::clone(&source)],
                &ReadOptions::default(),
                &Null,
                width,
            )
            .expect("the corpus extracts");
            walls[at].push(started.elapsed().as_secs_f64());
            cpus[at].push(cpu_seconds() - cpu_before);
            assert_eq!(report.members, 4060, "the same corpus in every cell");
            // The sweep is a WAIT: whatever this floor dispatches, it
            // dispatches the same way in every cell. Asserted against the
            // FIRST cell's own count rather than against a figure, so the
            // check holds at a floor that dispatches nothing as well as at
            // one that dispatches everything.
            let decoded = rarkit::probe::decoded_members();
            match on_the_walk {
                None => on_the_walk = Some(decoded),
                Some(first) => assert_eq!(
                    decoded, first,
                    "the sweep is a WAIT and dispatches exactly as before"
                ),
            }
        }
    }
    rarkit::probe::set_task_spin(None);
    let median = |v: &[f64]| {
        let mut v = v.to_vec();
        v.sort_by(f64::total_cmp);
        v[v.len() / 2]
    };
    for (at, spin) in cells.iter().enumerate() {
        println!(
            "worker sweep {spin:>3} us: wall median {:.4} s (min {:.4}), cpu median {:.4} s, \
             {} samples",
            median(&walls[at]),
            walls[at].iter().copied().fold(f64::MAX, f64::min),
            median(&cpus[at]),
            walls[at].len()
        );
    }
}
