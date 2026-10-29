//! The warm-abreast work's CEILING PROBE:
//! what a team of readers KEPT ACROSS VOLUME FILES can and cannot buy a
//! stored member posted in small volumes, counted before anything is built
//! in the engine. No archive is parsed: the files named are read whole, in
//! the order given, as one stream, which is what a stored member's
//! fragments are but for a few hundred header bytes a volume.
//!
//!     cargo run --release --example f_abreast_probe -- \
//!         READERS JOB_KIB REQUEST_KIB WINDOW_KIB CRC FILE...
//!
//! - `READERS` threads are started ONCE and kept to the end; 0 reads on the
//!   calling thread alone, with no hand-over at all.
//! - A JOB is `JOB_KIB` of the stream cut inside one file (a file's tail
//!   is a short job), or the whole file where `JOB_KIB` is 0: the second
//!   is one reader a volume file, each file read in order by one thread.
//! - A job is read in requests of `REQUEST_KIB` into its reader's own
//!   buffer, which starts on a 4 KiB boundary (`read::wide`'s `ALIGN`).
//! - A job is dispatched only while the bytes dispatched and not yet JOINED
//!   in stream order, with it, are within `WINDOW_KIB` (one job always
//!   may be): spec F 3.7.2's read-ahead, as `read::wide` keeps it.
//! - `CRC` 1 hashes every request with the engine's own CRC32 kernel
//!   (`rarkit::checksum::crc32`) on the reader; 0 reads only. The join of
//!   two CRC32s is a table shift a job (`Crc32::append`, not public), so
//!   the dispatching thread folds the values instead: its cost is not the read's.
//! - A file is opened when its first job is dispatched and closed when its
//!   last is joined; `peak_open` is the most open at once.
//! - `PROBE_ADVISE=1` in the environment advises each file as read in
//!   order at its open (Linux's `POSIX_FADV_SEQUENTIAL`, which rarfast
//!   gives a volume it reads in order); nothing on any other system.
//!
//! One line out: the bytes, the jobs, the requests, the opens, the most
//! files open at once, the fold and the wall of the read alone.

use std::collections::VecDeque;
use std::fs::File;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const ALIGN: usize = 4096;

#[cfg(unix)]
fn read_at(file: &File, into: &mut [u8], at: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, into, at)
}

#[cfg(windows)]
fn read_at(file: &File, into: &mut [u8], at: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, into, at)
}

/// Advise `file` as read in order, where the system has such advice.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn advise_in_order(file: &File) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: the descriptor is this open file's own, and the call reads
    // and writes no memory of ours.
    let _ = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
}

#[cfg(not(target_os = "linux"))]
fn advise_in_order(_file: &File) {}

/// A job: `len` bytes at `at` of file `index`, read in requests.
struct Job {
    seq: u64,
    file: Arc<File>,
    at: u64,
    len: u64,
}

/// A job's answer: its place in the stream, its fold and its requests.
struct Done {
    seq: u64,
    len: u64,
    fold: u32,
    requests: u64,
}

struct Buffer {
    raw: Vec<u8>,
    at: usize,
    len: usize,
}

impl Buffer {
    fn new(len: usize) -> Buffer {
        let raw = vec![0u8; len + ALIGN];
        let at = match raw.as_ptr().align_offset(ALIGN) {
            at if at < ALIGN => at,
            _ => 0,
        };
        Buffer { raw, at, len }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.raw[self.at..self.at + self.len]
    }
}

fn answer(job: Job, buf: &mut Buffer, crc: bool) -> Done {
    let mut done = 0u64;
    let mut fold = 0u32;
    let mut requests = 0u64;
    let request = buf.len as u64;
    while done < job.len {
        let want = (job.len - done).min(request) as usize;
        let into = &mut buf.bytes_mut()[..want];
        let mut got = 0usize;
        while got < want {
            let n = read_at(&job.file, &mut into[got..], job.at + done + got as u64)
                .expect("a volume file reads");
            assert!(n > 0, "a volume file ended inside a job");
            got += n;
            requests += 1;
        }
        if crc {
            fold = fold.rotate_left(1) ^ rarkit::checksum::crc32(into);
        }
        done += want as u64;
    }
    Done {
        seq: job.seq,
        len: job.len,
        fold,
        requests,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 6 {
        eprintln!("f_abreast_probe READERS JOB_KIB REQUEST_KIB WINDOW_KIB CRC FILE...");
        std::process::exit(2);
    }
    let number = |i: usize| args[i].parse::<u64>().expect("a number");
    let readers = number(0) as usize;
    let job_len = number(1) << 10;
    let request = ((number(2) << 10) as usize).max(ALIGN);
    let window = number(3) << 10;
    let crc = number(4) != 0;
    let paths = &args[5..];
    let advise = std::env::var("PROBE_ADVISE").is_ok_and(|v| v.trim() == "1");
    let sizes: Vec<u64> = paths
        .iter()
        .map(|p| std::fs::metadata(p).expect("a volume file").len())
        .collect();

    let started = Instant::now();
    let (job_tx, job_rx) = channel::<Job>();
    let job_rx: Arc<Mutex<Receiver<Job>>> = Arc::new(Mutex::new(job_rx));
    let (done_tx, done_rx) = channel::<Done>();
    let team: Vec<_> = (0..readers)
        .map(|_| {
            let jobs = Arc::clone(&job_rx);
            let done_tx = done_tx.clone();
            std::thread::spawn(move || {
                let mut buf = Buffer::new(request);
                loop {
                    let job = jobs.lock().expect("the job queue").recv();
                    let Ok(job) = job else { break };
                    if done_tx.send(answer(job, &mut buf, crc)).is_err() {
                        break;
                    }
                }
            })
        })
        .collect();
    drop(done_tx);
    let mut own = Buffer::new(request);

    // The stream position of the next job: the file, and the offset in it.
    let (mut file_at, mut offset) = (0usize, 0u64);
    // The files open: (index, handle, jobs of it not yet joined, all sent).
    let mut open: VecDeque<(usize, Arc<File>, u64, bool)> = VecDeque::new();
    // Jobs dispatched and not joined, in stream order: (file, len, answer).
    let mut flight: VecDeque<(usize, u64, Option<Done>)> = VecDeque::new();
    let (mut sent, mut joined) = (0u64, 0u64);
    let (mut bytes, mut jobs, mut requests, mut opens, mut peak_open) = (0u64, 0u64, 0u64, 0u64, 0);
    let mut in_window = 0u64;
    let mut fold = 0u32;
    loop {
        // Dispatch while the window has room.
        while file_at < paths.len() {
            if sizes[file_at] == offset {
                if let Some(last) = open.back_mut() {
                    if last.0 == file_at {
                        last.3 = true;
                    }
                }
                file_at += 1;
                offset = 0;
                continue;
            }
            let rest = sizes[file_at] - offset;
            let len = if job_len == 0 {
                rest
            } else {
                rest.min(job_len)
            };
            if in_window != 0 && in_window + len > window {
                break;
            }
            if open.back().is_none_or(|o| o.0 != file_at) {
                let file = Arc::new(File::open(&paths[file_at]).expect("a volume file opens"));
                if advise {
                    advise_in_order(&file);
                }
                open.push_back((file_at, file, 0, false));
                opens += 1;
                peak_open = peak_open.max(open.len());
            }
            let slot = open.back_mut().expect("just opened");
            slot.2 += 1;
            let job = Job {
                seq: sent,
                file: Arc::clone(&slot.1),
                at: offset,
                len,
            };
            flight.push_back((file_at, len, None));
            if readers == 0 {
                let done = answer(job, &mut own, crc);
                flight.back_mut().expect("just pushed").2 = Some(done);
            } else {
                job_tx.send(job).expect("the team is alive");
            }
            sent += 1;
            in_window += len;
            offset += len;
        }
        if flight.is_empty() {
            break;
        }
        // Join the lowest job answered, in stream order.
        if let Some((index, len, done)) = flight.pop_front_if(|f| f.2.is_some()) {
            let done = done.expect("checked");
            fold = fold.rotate_left(1) ^ done.fold;
            bytes += done.len;
            requests += done.requests;
            jobs += 1;
            joined += 1;
            in_window -= len;
            let first = open.front_mut().expect("its file is open");
            assert_eq!(first.0, index);
            first.2 -= 1;
            if first.2 == 0 && (first.3 || index + 1 < file_at) {
                open.pop_front();
            }
            continue;
        }
        let done = done_rx.recv().expect("an answer is coming");
        let at = (done.seq - joined) as usize;
        flight[at].2 = Some(done);
    }
    drop(job_tx);
    for reader in team {
        reader.join().expect("a reader ends");
    }
    println!(
        "PROBE bytes={bytes} jobs={jobs} requests={requests} opens={opens} peak_open={peak_open} fold={fold:08x} wall_ms={:.3}",
        started.elapsed().as_secs_f64() * 1e3
    );
}
