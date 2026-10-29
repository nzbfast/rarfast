//! The wide-read breadth work's DESCRIPTOR PROBE: where the
//! time of `read::wide`'s readers goes when they all read ONE file, and
//! whether a descriptor a reader changes it, counted before anything is
//! built in the engine. No archive is parsed: the files named are read
//! whole, in the order given, as one stream, which is what a stored
//! member's packed bytes are but for a few hundred header bytes a volume.
//!
//!     cargo run --release --example f_wide_fd_probe -- \
//!         READERS PIECE_KIB WINDOW CRC FDS FILE...
//!
//! - `READERS` threads are started once and kept to the end, as
//!   `read::wide` keeps its workers for a range.
//! - A PIECE is `PIECE_KIB` of the stream cut inside one file (a file's
//!   tail is a short piece), read by one `pread` into its reader's own
//!   buffer, which starts on a 4 KiB boundary (`read::wide`'s `ALIGN`).
//! - A piece is dispatched only while fewer than `WINDOW` pieces are
//!   dispatched and not yet JOINED in stream order (0 is `READERS`, which
//!   is `read::wide`'s own window): spec F 3.7.2's read-ahead.
//! - `CRC` 1 hashes every piece with the engine's own CRC32 kernel
//!   (`rarkit::checksum::crc32`) on its reader; 0 reads only.
//! - `FDS` says through what a reader reads a file:
//!   `shared`, one descriptor a file for every reader, which is what
//!   `read::wide` does today; `each`, a descriptor of its own that the
//!   reader opens by path the first time it is given a piece of the file;
//!   `dup`, a duplicate of the one descriptor (`File::try_clone`), which is
//!   a second NUMBER for the same open file, so it tells a wait kept by the
//!   open file apart from one kept by the file itself.
//! - `PROBE_FILE_JOBS=1` in the environment makes a JOB a WHOLE FILE, read
//!   in order by one reader in requests of `PIECE_KIB`, and `WINDOW` then
//!   counts files: readers each in a file of their own, the same requests.
//!
//! Each reader times three things with the monotonic clock: waiting for a
//! piece, the `pread`, and the hash. One line out: the bytes, the pieces,
//! the reads, the opens, the fold, the wall of the read alone, and the
//! readers' three sums. CPU seconds (user and system apart) and the peak
//! are the runner's to take from the process.

use std::collections::VecDeque;
use std::fs::File;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ALIGN: usize = 4096;

#[cfg(unix)]
fn read_at(file: &File, into: &mut [u8], at: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, into, at)
}

#[cfg(windows)]
fn read_at(file: &File, into: &mut [u8], at: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, into, at)
}

/// Through what a reader reads a file.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Fds {
    Shared,
    Each,
    Dup,
}

/// A job: `len` bytes at `at` of file `index`, one piece unless a job is a
/// whole file.
struct Job {
    seq: u64,
    index: usize,
    file: Arc<File>,
    at: u64,
    len: u64,
}

/// A piece's answer: its place in the stream and its CRC32.
struct Done {
    seq: u64,
    len: u64,
    crc: u32,
}

/// What one reader did, summed when it ends.
#[derive(Default)]
struct Spent {
    wait: Duration,
    read: Duration,
    hash: Duration,
    open: Duration,
    reads: u64,
    opens: u64,
}

struct Buffer {
    raw: Vec<u8>,
    at: usize,
}

impl Buffer {
    fn new(len: usize) -> Buffer {
        let raw = vec![0u8; len + ALIGN];
        let at = match raw.as_ptr().align_offset(ALIGN) {
            at if at < ALIGN => at,
            _ => 0,
        };
        Buffer { raw, at }
    }
}

/// One reader: pieces until the queue ends.
fn reader(
    jobs: &Mutex<Receiver<Job>>,
    done: &std::sync::mpsc::Sender<Done>,
    paths: &[String],
    piece: usize,
    crc: bool,
    fds: Fds,
) -> Spent {
    let mut spent = Spent::default();
    let mut buf = Buffer::new(piece);
    // This reader's own descriptor of the file it read last: a stream is
    // read in order, so one is enough.
    let mut own: Option<(usize, File)> = None;
    loop {
        let waited = Instant::now();
        let job = jobs.lock().expect("the job queue").recv();
        spent.wait += waited.elapsed();
        let Ok(job) = job else { break };
        if fds != Fds::Shared && own.as_ref().is_none_or(|o| o.0 != job.index) {
            let opened = Instant::now();
            let file = match fds {
                Fds::Each => File::open(&paths[job.index]).expect("a file opens again"),
                _ => job.file.try_clone().expect("a descriptor duplicates"),
            };
            spent.open += opened.elapsed();
            spent.opens += 1;
            own = Some((job.index, file));
        }
        let file: &File = match &own {
            Some((_, file)) if fds != Fds::Shared => file,
            _ => &job.file,
        };
        let mut value = 0u32;
        let mut done_bytes = 0u64;
        while done_bytes < job.len {
            let want = (job.len - done_bytes).min(piece as u64) as usize;
            let into = &mut buf.raw[buf.at..buf.at + want];
            let began = Instant::now();
            let mut got = 0usize;
            while got < want {
                let n = read_at(file, &mut into[got..], job.at + done_bytes + got as u64)
                    .expect("a file reads");
                assert!(n > 0, "a file ended inside a piece");
                got += n;
                spent.reads += 1;
            }
            let read = Instant::now();
            spent.read += read - began;
            if crc {
                value = value.rotate_left(1) ^ rarkit::checksum::crc32(into);
                spent.hash += read.elapsed();
            }
            done_bytes += want as u64;
        }
        let answer = Done {
            seq: job.seq,
            len: job.len,
            crc: value,
        };
        if done.send(answer).is_err() {
            break;
        }
    }
    spent
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 6 {
        eprintln!("f_wide_fd_probe READERS PIECE_KIB WINDOW CRC shared|each|dup FILE...");
        std::process::exit(2);
    }
    let number = |i: usize| args[i].parse::<u64>().expect("a number");
    let readers = (number(0) as usize).max(1);
    let piece = ((number(1) << 10) as usize).max(ALIGN);
    let window = match number(2) {
        0 => readers as u64,
        n => n,
    };
    let crc = number(3) != 0;
    let fds = match args[4].as_str() {
        "shared" => Fds::Shared,
        "each" => Fds::Each,
        "dup" => Fds::Dup,
        other => panic!("FDS is shared, each or dup, not {other}"),
    };
    let file_jobs = std::env::var("PROBE_FILE_JOBS").is_ok_and(|v| v.trim() == "1");
    let paths: Arc<Vec<String>> = Arc::new(args[5..].to_vec());
    let sizes: Vec<u64> = paths
        .iter()
        .map(|p| std::fs::metadata(p).expect("a file").len())
        .collect();

    let started = Instant::now();
    let (job_tx, job_rx) = channel::<Job>();
    let job_rx = Arc::new(Mutex::new(job_rx));
    let (done_tx, done_rx) = channel::<Done>();
    let team: Vec<_> = (0..readers)
        .map(|_| {
            let jobs = Arc::clone(&job_rx);
            let done_tx = done_tx.clone();
            let paths = Arc::clone(&paths);
            std::thread::spawn(move || reader(&jobs, &done_tx, &paths, piece, crc, fds))
        })
        .collect();
    drop(done_tx);

    // The stream position of the next piece: the file, and the offset in it.
    let (mut file_at, mut offset) = (0usize, 0u64);
    let mut open: Option<(usize, Arc<File>)> = None;
    // Pieces dispatched and not joined, in stream order.
    let mut flight: VecDeque<Option<Done>> = VecDeque::new();
    let (mut sent, mut joined) = (0u64, 0u64);
    let (mut bytes, mut opens) = (0u64, 0u64);
    let mut fold = 0u32;
    loop {
        while file_at < paths.len() && sent - joined < window {
            if sizes[file_at] == offset {
                file_at += 1;
                offset = 0;
                continue;
            }
            if open.as_ref().is_none_or(|o| o.0 != file_at) {
                let file = File::open(&paths[file_at]).expect("a file opens");
                open = Some((file_at, Arc::new(file)));
                opens += 1;
            }
            let rest = sizes[file_at] - offset;
            let len = if file_jobs {
                rest
            } else {
                rest.min(piece as u64)
            };
            let file = Arc::clone(&open.as_ref().expect("just opened").1);
            let job = Job {
                seq: sent,
                index: file_at,
                file,
                at: offset,
                len,
            };
            job_tx.send(job).expect("the team is alive");
            flight.push_back(None);
            sent += 1;
            offset += len;
        }
        if flight.is_empty() {
            break;
        }
        if let Some(done) = flight.pop_front_if(|f| f.is_some()) {
            let done = done.expect("checked");
            fold = fold.rotate_left(1) ^ done.crc;
            bytes += done.len;
            joined += 1;
            continue;
        }
        let done = done_rx.recv().expect("an answer is coming");
        let at = (done.seq - joined) as usize;
        flight[at] = Some(done);
    }
    drop(job_tx);
    let mut all = Spent::default();
    for reader in team {
        let spent = reader.join().expect("a reader ends");
        all.wait += spent.wait;
        all.read += spent.read;
        all.hash += spent.hash;
        all.open += spent.open;
        all.reads += spent.reads;
        all.opens += spent.opens;
    }
    let wall = started.elapsed();
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    println!(
        "PROBE readers={readers} piece_kib={} window={window} crc={} fds={} file_jobs={} bytes={bytes} pieces={joined} reads={} opens={} fold={fold:08x} wall_ms={:.3} read_ms={:.3} hash_ms={:.3} wait_ms={:.3} open_ms={:.3}",
        piece >> 10,
        crc as u8,
        args[4],
        file_jobs as u8,
        all.reads,
        opens + all.opens,
        ms(wall),
        ms(all.read),
        ms(all.hash),
        ms(all.wait),
        ms(all.open),
    );
}
